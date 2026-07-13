using module "..\ORCA.psm1"

# HTML output — Fluent Light redesign (mockup A port).
# Contract preserved with the rest of the framework:
#   * First 2 lines of the generated file are `<!-- checkjson\n<base64>\nendcheckjson -->`
#     so GetHistoricData() (and any external trend tooling) can detect prior ORCA reports.
#   * When -EmbedConfiguration is set, the full Collection is gzipped + base64 into
#     $MetaObject.Config exactly as before so Get-ORCAReportEmbeddedConfig keeps working.
#   * All rendering is now client-side from a single inline JSON island
#     <script id="report-data" type="application/json">...</script> rather than emitted HTML,
#     which keeps the file diffable and self-contained for sharing.

class html : ORCAOutput
{
    $OutputDirectory = $null
    $DisplayReport   = $true
    $EmbedConfiguration = $false
    # $ShowSurvey is inherited from ORCAOutput — do not redeclare here or PowerShell
    # raises "Ambiguous match found" when constructing the class.

    html()
    {
        $this.Name = "HTML"
    }

    [string] GetOutputDir()
    {
        if ($null -eq $this.OutputDirectory) { return $this.DefaultOutputDirectory }
        return $this.OutputDirectory
    }

    # Walk the output directory for prior ORCA reports for this tenant and read the
    # first 2 lines of each. Returns an array of decoded historic MetaObjects with the
    # current one appended last so the trend always has at least 1 datum.
    [Object[]] GetHistoricData($Current, $Tenant)
    {
        $HistoricData = @()

        try
        {
            $Path = $this.GetOutputDir() + "\ORCA-$Tenant-*.html"
            $MatchingReports = Get-ChildItem $Path -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
            foreach ($MatchReport in $MatchingReports)
            {
                $FirstLines = Get-Content $MatchReport -First 2 -ErrorAction SilentlyContinue
                if ($FirstLines -and $FirstLines[0] -like "<!-- checkjson*")
                {
                    $DecodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($FirstLines[1]))
                    $Object = ConvertFrom-Json $DecodedText
                    if ($Object.Tenant -eq $Tenant)
                    {
                        $HistoricData += $Object
                    }
                }
            }
        }
        catch
        {
            # Best-effort. A broken historic file should never block the new report.
        }

        $HistoricData += $Current
        return $HistoricData
    }

    RunOutput($Checks, $Collection, [ORCAConfigLevel]$AssessmentLevel)
    {
        # ---- Tenant + report metadata ------------------------------------------------
        $TenantDomain = ($Collection["AcceptedDomains"] | Where-Object { $_.InitialDomain -eq $true }).DomainName
        $Tenant       = ($TenantDomain -split '\.')[0]
        $ReportDate   = Get-Date -Format 'dd-MMM-yyyy HH:mm'

        # ---- Server-side check normalisation -----------------------------------------
        # Project each ORCACheck/ORCACheckConfig into ordered hashtables so:
        #   1. PS 5.1 vs 7 enum serialisation differences disappear (we cast to int).
        #   2. We can add Subsection / rename Area without mutating the shared $Checks
        #      objects that the other output modules also consume.
        $NormalisedChecks = foreach ($c in $Checks)
        {
            # Apply area renames / moves first so they cascade into Subsection logic below.
            $area = $c.Area
            if ($area -eq 'Anti-Spam Policies') { $area = 'Anti-Spam' }
            if ($c.Name -eq 'Honor DMARC Policy' -and $area -eq 'Anti-Phishing Policy')
            {
                $area = 'Microsoft Defender for Office 365 Policies'
            }
            if ($area -eq 'Microsoft Defender for Office 365 Policies' -and $c.Name -match 'Teams')
            {
                $area = 'Microsoft Teams protection'
            }

            # Subsection assignment for the MDO area, name-pattern based so it survives
            # check additions/renames without further code changes.
            $subsection = $null
            if ($area -eq 'Microsoft Defender for Office 365 Policies')
            {
                $subsection = switch -Regex ($c.Name)
                {
                    '^Safe Links|Safe Link'                                                   { 'Safe Links policy'; break }
                    '^Safe Attachments|^Safe attachments|^Common Attachment|Safe Documents'   { 'Safe Attachments policy'; break }
                    '^Priority Account'                                                        { 'Priority Account Protection'; break }
                    'User report'                                                              { 'User reported settings'; break }
                    default                                                                    { 'Anti-phishing policy' }
                }
            }

            $configRows = @()
            foreach ($cfg in $c.Config)
            {
                $configRows += [ordered]@{
                    Object           = $cfg.Object
                    ConfigItem       = $cfg.ConfigItem
                    ConfigData       = $cfg.ConfigData
                    ConfigPolicyGuid = $cfg.ConfigPolicyGuid
                    ConfigDisabled   = [bool]$cfg.ConfigDisabled
                    ConfigWontApply  = [bool]$cfg.ConfigWontApply
                    ConfigReadonly   = [bool]$cfg.ConfigReadonly
                    InfoText         = $cfg.InfoText
                    Level            = [int]$cfg.Level
                    LevelText        = $cfg.Level.ToString()
                    ResultStandard   = [int]$cfg.ResultStandard
                    ResultStrict     = [int]$cfg.ResultStrict
                }
            }

            [ordered]@{
                Name               = $c.Name
                Area               = $area
                Importance         = $c.Importance
                PassText           = $c.PassText
                FailRecommendation = $c.FailRecommendation
                ObjectType         = $c.ObjectType
                ItemName           = $c.ItemName
                DataType           = $c.DataType
                Links              = $c.Links
                Completed          = [bool]$c.Completed
                CheckFailed        = [bool]$c.CheckFailed
                CheckFailureReason = $c.CheckFailureReason
                SkipInReport       = [bool]$c.SkipInReport
                Result             = [int]$c.Result
                ResultStandard     = [int]$c.ResultStandard
                ResultStrict       = [int]$c.ResultStrict
                ChiValue           = [int]$c.ChiValue
                Config             = $configRows
                Subsection         = $subsection
            }
        }

        # ---- Summary counts (driven by the normalised list) --------------------------
        $RecommendationCount = @($NormalisedChecks | Where-Object { $_.Result -eq [int][ORCAResult]::Fail          -and $_.Completed }).Count
        $OKCount             = @($NormalisedChecks | Where-Object { $_.Result -eq [int][ORCAResult]::Pass          -and $_.Completed }).Count
        $InfoCount           = @($NormalisedChecks | Where-Object { $_.Result -eq [int][ORCAResult]::Informational -and $_.Completed }).Count

        # ---- MetaObject — drives BOTH the checkjson header and the inline JSON ------
        $MetaObject = [ordered]@{
            Tenant                = $Tenant
            TenantDomain          = $TenantDomain
            ReportDate            = $ReportDate
            Version               = $this.VersionCheck.Version.ToString()
            Config                = $null
            EmbeddedConfiguration = $this.EmbedConfiguration
            CHI                   = $Collection["CHI"]
            Summary               = [ordered]@{
                Recommendation = $RecommendationCount
                OK             = $OKCount
                InfoCount      = $InfoCount
            }
            Checks                = $NormalisedChecks
        }

        # ---- Optional: embed gzipped CliXml of the full Collection -------------------
        if ($this.EmbedConfiguration -eq $true)
        {
            $TempFileXML = New-TemporaryFile
            $ZipTempLoc  = New-TemporaryFile
            $ZipPath     = "$($ZipTempLoc.ToString()).zip"

            $Collection | Export-Clixml -Path $TempFileXML
            Compress-Archive -Path $TempFileXML -DestinationPath $ZipPath

            if ($global:PSVersionTable.PSEdition -eq 'Core')
            {
                $MetaObject.Config = [Convert]::ToBase64String((Get-Content -Path $ZipPath -AsByteStream))
            }
            else
            {
                $MetaObject.Config = [Convert]::ToBase64String((Get-Content -Path $ZipPath -Encoding byte))
            }
            $MetaObject.EmbeddedConfiguration = $true

            Remove-Item -Path $TempFileXML; Remove-Item -Path $ZipTempLoc; Remove-Item -Path $ZipPath
        }

        # ---- Historic trend: compact prior reports + current so the chart wires up ---
        $HistoricRaw   = $this.GetHistoricData([PSCustomObject]$MetaObject, $Tenant)
        $HistoricTrend = @()
        foreach ($h in $HistoricRaw)
        {
            $HistoricTrend += [ordered]@{
                ReportDate = $h.ReportDate
                Rec        = if ($h.Summary) { [int]$h.Summary.Recommendation } else { 0 }
                OK         = if ($h.Summary) { [int]$h.Summary.OK }             else { 0 }
                Info       = if ($h.Summary) { [int]$h.Summary.InfoCount }      else { 0 }
            }
        }
        $MetaObject.HistoricCount = $HistoricTrend.Count
        $MetaObject.HistoricData  = $HistoricTrend

        # ---- Serialise. -Compress keeps the file lean; </ -> <\/ guard means the
        # ---- inline <script> block can never be terminated by data inside the JSON.
        $Json        = $MetaObject | ConvertTo-Json -Depth 100 -Compress
        $Json        = $Json -replace '</', '<\/'
        $EncodedText = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Json))

        # ---- Build server-side alert banners (rendered above the hero) --------------
        $Alerts = @()
        if ($this.EmbedConfiguration -eq $true)
        {
            $Alerts += @"
<div class="alert alert-info"><b>Embedded configuration present.</b> This report contains a snapshot of the full tenant configuration. To re-read it, run <code>Get-ORCAReportEmbeddedConfig -File &lt;path&gt;</code>. Treat this file as confidential.</div>
"@
        }
        if ($this.VersionCheck.GalleryCheck -and $this.VersionCheck.Updated -eq $false)
        {
            $Alerts += @"
<div class="alert alert-danger"><b>ORCA is out of date.</b> You are running version $($this.VersionCheck.Version) but version $($this.VersionCheck.GalleryVersion) is available. Run <code>Update-Module ORCA</code> to refresh the definitions.</div>
"@
        }
        if (-not $this.VersionCheck.GalleryCheck)
        {
            $Alerts += @"
<div class="alert alert-warning"><b>Version check skipped.</b> Periodically run <code>Update-Module ORCA</code> to pick up the latest check definitions.</div>
"@
        }
        if ($this.VersionCheck.Preview -eq $true)
        {
            $Alerts += @"
<div class="alert alert-warning"><b>Preview build.</b> Preview versions may contain errors. Verify the results before applying configuration changes.</div>
"@
        }
        if (-not ($Collection["Services"] -band [ORCAService]::MDO))
        {
            $Alerts += @"
<div class="alert alert-danger"><b>Microsoft Defender for Office 365 not detected on this tenant.</b> MDO-specific checks are skipped; remaining results reflect base EOP configuration only.</div>
"@
        }
        $FailedChecks = @($NormalisedChecks | Where-Object { $_.CheckFailed })
        if ($FailedChecks.Count -gt 0)
        {
            $failNames = ($FailedChecks | ForEach-Object { $_.Name }) -join ', '
            $Alerts += @"
<div class="alert alert-danger"><b>$($FailedChecks.Count) check(s) failed to run:</b> $failNames. See the PowerShell host output for details.</div>
"@
        }
        $AlertHtml = if ($Alerts.Count) { "<section class=`"alerts`">$($Alerts -join "`n")</section>" } else { '' }

        # ---- Optional QR survey block on the hero. Gated by $this.ShowSurvey. ------
        $SurveyHtml = ''
        if ($this.ShowSurvey -eq $true)
        {
            $SurveyHtml = @"
        <aside class="rh-survey">
          <a href="http://aka.ms/orcasurvey" target="_blank" rel="noopener" title="Take the ORCA feedback survey">
            <img class="rh-qr" src="data:image/png;base64,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" alt="Scan to take the ORCA feedback survey" />
          </a>
          <div class="rh-survey-text">
            <div class="rh-survey-title">Help shape the next ORCA</div>
            <p>Two minutes of your feedback steers the roadmap. Scan, or visit <a href="http://aka.ms/orcasurvey" target="_blank" rel="noopener">aka.ms/orcasurvey</a>.</p>
          </div>
        </aside>
"@
        }

        # ---- Inline CSS (Fluent Light tokens — verbatim from the validated mockup) -
        # Single-quoted here-string: no PS interpolation, so all CSS `$` would be safe,
        # though there are none today.
        $Css = @'
:root {
    --fnt: "Segoe UI Variable","Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
    --bg: #faf9f8;
    --surface: #ffffff;
    --surface-2: #f3f2f1;
    --border: #e1dfdd;
    --border-strong: #c8c6c4;
    --text: #201f1e;
    --text-secondary: #605e5c;
    --text-tertiary: #8a8886;
    --primary: #0078d4;
    --primary-hover: #106ebe;
    --primary-bg: #deecf9;
    --success: #107c10;
    --success-bg: #dff6dd;
    --warning: #ca5010;
    --warning-bg: #fed9cc;
    --danger: #a4262c;
    --danger-bg: #fde7e9;
    --info: #605e5c;
    --info-bg: #f3f2f1;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.06);
    --shadow-md: 0 1.6px 3.6px rgba(0,0,0,0.10), 0 0.3px 0.9px rgba(0,0,0,0.07);
    --radius: 4px;
}
* { box-sizing: border-box; }
html, body { margin:0; padding:0; background: var(--bg); color: var(--text); font-family: var(--fnt); font-size: 14px; line-height: 1.5; }

.app-header { position: sticky; top:0; z-index: 50; background: var(--surface); border-bottom: 1px solid var(--border); box-shadow: var(--shadow-sm); }
.app-header-inner { display:flex; align-items:center; gap: 16px; padding: 0 24px; height: 48px; }
.brand { display:flex; align-items:center; gap: 10px; font-weight: 600; font-size: 15px; color: var(--text); }
.brand-mark { width: 22px; height: 22px; display:inline-grid; grid-template-columns: 1fr 1fr; gap: 2px; }
.brand-mark span { display:block; }
.brand-mark span:nth-child(1){ background: #f25022; }
.brand-mark span:nth-child(2){ background: #7fba00; }
.brand-mark span:nth-child(3){ background: #00a4ef; }
.brand-mark span:nth-child(4){ background: #ffb900; }
.brand-product { font-weight: 600; color: var(--primary); }
.brand-sub { font-weight: 400; color: var(--text-secondary); margin-left: 6px; }
.header-spacer { flex: 1; }
.header-meta { color: var(--text-secondary); font-size: 12px; display:flex; gap:16px; }
.header-meta b { color: var(--text); font-weight: 600; }

.layout { display: grid; grid-template-columns: 260px 1fr; min-height: calc(100vh - 48px); transition: grid-template-columns .18s ease; }
body.sb-collapsed .layout { grid-template-columns: 0 1fr; }
body.sb-collapsed .sidebar { display: none; }
.sidebar { background: var(--surface); border-right: 1px solid var(--border); padding: 16px 0; position: sticky; top: 48px; align-self: start; max-height: calc(100vh - 48px); overflow-y: auto; }
.sb-toggle { position: fixed; top: 56px; left: 252px; width: 22px; height: 30px; background: var(--surface); border: 1px solid var(--border); border-left: none; border-radius: 0 4px 4px 0; cursor: pointer; z-index: 50; color: var(--text-secondary); font-size: 14px; line-height: 1; display: flex; align-items: center; justify-content: center; transition: left .18s ease; box-shadow: 1px 0 3px rgba(0,0,0,.06); }
.sb-toggle:hover { background: var(--surface-2); color: var(--text); }
body.sb-collapsed .sb-toggle { left: 0; }
.sb-toggle .chev { display: inline-block; transition: transform .18s ease; }
body.sb-collapsed .sb-toggle .chev { transform: rotate(180deg); }
.sidebar-title { padding: 4px 20px 8px; font-size: 11px; font-weight: 600; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: .5px; }
.sidebar a { display:flex; align-items:center; justify-content: space-between; gap: 8px; padding: 6px 20px; color: var(--text); text-decoration: none; font-size: 13px; border-left: 3px solid transparent; }
.sidebar a:hover { background: var(--surface-2); }
.sidebar a.active { background: var(--primary-bg); border-left-color: var(--primary); font-weight: 600; }
.sidebar a .count { color: var(--text-secondary); font-size: 12px; }

/* Sub-navigation items rendered under MDO area in the sidebar.
   Indented, lighter border and smaller text to visually nest under the parent. */
.sidebar a.sub-nav { padding-left: 32px; font-size: 12px; border-left-color: transparent; color: var(--text-secondary); }
.sidebar a.sub-nav:hover { background: var(--surface-2); color: var(--text); }
.sidebar a.sub-nav.active { background: var(--primary-bg); border-left-color: var(--primary); color: var(--primary); font-weight: 600; }

.main { padding: 24px 32px 64px; max-width: 1800px; grid-column: 2; min-width: 0; }

.alerts { display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px; }
.alert { padding: 10px 14px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--surface); box-shadow: var(--shadow-sm); font-size: 13px; line-height: 1.5; border-left: 4px solid var(--border-strong); }
.alert b { color: var(--text); }
.alert code { background: var(--surface-2); padding: 1px 6px; border-radius: 3px; font-size: 12px; font-family: Consolas, "Courier New", monospace; color: var(--text); }
.alert-info { border-left-color: var(--primary); }
.alert-warning { border-left-color: var(--warning); }
.alert-danger { border-left-color: var(--danger); }

.report-cover { background: linear-gradient(135deg, #0078d4 0%, #004578 100%); color: #ffffff; border-radius: var(--radius); padding: 36px 40px; margin-bottom: 14px; box-shadow: 0 4px 16px rgba(0, 69, 120, 0.18); position: relative; overflow: hidden; display: flex; align-items: center; gap: 28px; }
.report-cover::after { content: ''; position: absolute; right: -60px; top: -60px; width: 240px; height: 240px; border-radius: 50%; background: rgba(255,255,255,0.06); pointer-events: none; }
.rh-main { flex: 1; min-width: 0; position: relative; z-index: 1; }
.rh-title { margin: 0 0 6px; font-size: 30px; font-weight: 700; color: #ffffff; line-height: 1.15; letter-spacing: 1.6px; text-transform: uppercase; }
.rh-subtitle { margin: 0 0 18px; font-size: 22px; font-weight: 400; color: rgba(255,255,255,0.92); line-height: 1.2; letter-spacing: 0.2px; }
.rh-meta { color: rgba(255,255,255,0.85); font-size: 13px; display: flex; flex-wrap: wrap; gap: 6px 22px; padding-top: 14px; border-top: 1px solid rgba(255,255,255,0.18); }
.rh-meta b { color: #ffffff; font-weight: 600; }

.rh-survey { flex: 0 0 auto; position: relative; z-index: 1; display: flex; align-items: center; gap: 14px; background: rgba(255,255,255,0.10); border: 1px solid rgba(255,255,255,0.22); border-radius: 8px; padding: 12px 14px; max-width: 340px; }
.rh-qr { width: 96px; height: 96px; display: block; background: #ffffff; padding: 6px; border-radius: 4px; flex: 0 0 96px; }
.rh-survey-text { color: #ffffff; font-size: 12px; line-height: 1.45; }
.rh-survey-title { font-size: 13px; font-weight: 600; margin-bottom: 4px; letter-spacing: 0.2px; }
.rh-survey-text p { margin: 0; color: rgba(255,255,255,0.92); }
.rh-survey-text a { color: #ffffff; text-decoration: underline; font-weight: 600; }

.report-intro { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--primary); border-radius: var(--radius); padding: 14px 20px; margin-bottom: 16px; box-shadow: var(--shadow-sm); }
.rh-intro { margin: 0; color: var(--text-secondary); font-size: 13px; line-height: 1.6; max-width: 1000px; }

/* User guide (README) panel rendered between the report intro and the Summary.
   Collapsible <details> element so first-time readers see the guidance and
   experienced users can hide it. No JS dependency — native disclosure widget. */
.user-guide { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 16px; box-shadow: var(--shadow-sm); overflow: hidden; scroll-margin-top: 60px; }
.user-guide > summary { cursor: pointer; padding: 14px 20px; font-weight: 600; font-size: 15px; color: var(--text); display: flex; align-items: center; gap: 10px; list-style: none; user-select: none; background: linear-gradient(180deg, var(--surface) 0%, var(--surface-2) 100%); }
.user-guide > summary::-webkit-details-marker { display: none; }
.user-guide > summary::before { content: "▸"; font-size: 11px; color: var(--text-secondary); transition: transform .15s ease; }
.user-guide[open] > summary::before { transform: rotate(90deg); }
.user-guide > summary .ug-badge { font-size: 10px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; color: var(--primary); background: var(--primary-bg); padding: 2px 8px; border-radius: 10px; }
.user-guide > summary .ug-hint { margin-left: auto; font-size: 12px; font-weight: 400; color: var(--text-secondary); }
.ug-body { padding: 18px 28px 24px; color: var(--text); font-size: 13px; line-height: 1.65; max-width: 1100px; border-top: 1px solid var(--border); }
.ug-body h3 { margin: 22px 0 8px; font-size: 14px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.ug-body h3:first-of-type { margin-top: 0; }
.ug-body p { margin: 0 0 10px; color: var(--text-secondary); }
.ug-body ul, .ug-body ol { margin: 6px 0 14px; padding-left: 22px; color: var(--text-secondary); }
.ug-body li { margin-bottom: 6px; }
.ug-body li b, .ug-body p b { color: var(--text); }
.ug-body code { background: var(--surface-2); padding: 1px 6px; border-radius: 3px; font-size: 12px; color: var(--text); font-family: Consolas, Menlo, monospace; }
.ug-callout { background: var(--primary-bg); border-left: 3px solid var(--primary); padding: 10px 14px; margin: 14px 0; border-radius: 4px; font-size: 12.5px; color: var(--text); }
.ug-callout b { color: var(--text); }
.ug-pill { display:inline-block; font-size: 11px; font-weight: 600; padding: 1px 7px; border-radius: 10px; margin-right: 4px; vertical-align: middle; }
.ug-pill.rec { background: rgba(202,79,18,.12); color: #8a3a0c; }
.ug-pill.ok { background: rgba(16,124,16,.12); color: #0e6b0e; }
.ug-pill.info { background: var(--primary-bg); color: var(--primary); }
.ug-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; margin: 8px 0 14px; }
.ug-card { border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; background: var(--surface); }
.ug-card b { display: block; margin-bottom: 4px; font-size: 13px; color: var(--text); }
.ug-card span { font-size: 12px; color: var(--text-secondary); line-height: 1.5; }
body.density-compact .user-guide > summary { padding: 10px 16px; font-size: 13px; }
body.density-compact .ug-body { padding: 14px 20px 18px; font-size: 12px; line-height: 1.55; }

body.density-compact .report-cover { padding: 22px 26px; margin-bottom: 10px; gap: 20px; }
body.density-compact .rh-title { font-size: 22px; letter-spacing: 1.4px; }
body.density-compact .rh-subtitle { font-size: 16px; margin-bottom: 12px; }
body.density-compact .rh-meta { font-size: 12px; padding-top: 10px; }
body.density-compact .rh-qr { width: 78px; height: 78px; flex-basis: 78px; }
body.density-compact .rh-survey { padding: 10px 12px; max-width: 300px; gap: 12px; }
body.density-compact .rh-survey-title { font-size: 12px; }
body.density-compact .rh-survey-text { font-size: 11px; line-height: 1.4; }
body.density-compact .report-intro { padding: 10px 16px; margin-bottom: 12px; }
body.density-compact .rh-intro { font-size: 12px; line-height: 1.5; }

@media (max-width: 1100px) {
    .report-cover { flex-wrap: wrap; }
    .rh-survey { max-width: none; width: 100%; }
}

.overview-grid { display: grid; grid-template-columns: 1fr; gap: 16px; margin-bottom: 16px; }
.overview-grid > * { min-width: 0; }
.overview-grid > .hero, .overview-grid > .trend-card { margin-bottom: 0; }
@media (min-width: 1500px) {
    .overview-grid { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); align-items: stretch; }
    .overview-grid > .trend-card { display: flex; flex-direction: column; }
    .overview-grid > .trend-card .trend-canvas-wrap { flex: 1; min-height: 180px; }
}

.subsection-head { margin: 18px 0 10px; padding: 8px 12px; background: #f5f9fd; border-left: 3px solid var(--primary); border-radius: 6px; display: flex; align-items: center; justify-content: space-between; }
.subsection-head:first-of-type { margin-top: 4px; }
.subsection-head h3 { margin: 0; font-size: 14px; font-weight: 600; color: var(--text); letter-spacing: 0.2px; }
.subsection-head .sub-count { font-size: 11px; color: var(--text-secondary); font-weight: 500; }
body.density-compact .subsection-head { padding: 6px 10px; margin: 12px 0 8px; }
body.density-compact .subsection-head h3 { font-size: 13px; }

body.density-compact .main { padding: 14px 20px 40px; }
body.density-compact .overview-grid { gap: 12px; margin-bottom: 12px; }
body.density-compact .hero { padding: 14px 18px; }
body.density-compact .hero h1 { font-size: 18px; margin-bottom: 2px; }
body.density-compact .hero .tenant { margin-bottom: 10px; }
body.density-compact .hero-stats { gap: 8px; }
body.density-compact .stat { padding: 8px 12px; }
body.density-compact .stat .v { font-size: 18px; }
body.density-compact .chi-block { margin-top: 10px; }
body.density-compact .chi-bar-wrap { height: 28px; }
body.density-compact .chi-bar-label { font-size: 14px; }
body.density-compact .chi-value-large { font-size: 26px; }
body.density-compact .chi-desc { font-size: 12px; margin-top: 6px; }
body.density-compact .trend-card { padding: 12px 16px; }
body.density-compact .trend-canvas-wrap { height: 140px; }
body.density-compact .toolbar { padding: 8px 12px; }

.hero { display: grid; grid-template-columns: 1fr 280px; gap: 24px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; margin-bottom: 16px; box-shadow: var(--shadow-sm); }
.hero h1 { margin: 0 0 4px; font-size: 22px; font-weight: 600; }
.hero .tenant { color: var(--text-secondary); font-size: 13px; margin-bottom: 16px; }
.hero-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
.stat { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--border-strong); border-radius: var(--radius); padding: 12px 14px; min-width: 0; }
.stat .v { font-size: 22px; font-weight: 600; line-height: 1.1; color: var(--text); }
.stat .l { font-size: 12px; color: var(--text-secondary); margin-top: 2px; overflow-wrap: anywhere; }
.stat.rec  { border-left-color: var(--warning); }
.stat.ok   { border-left-color: var(--success); }
.stat.info { border-left-color: var(--primary); }
.stat.total{ border-left-color: var(--text-secondary); }

.toolbar { position: sticky; top: 48px; z-index: 40; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px 14px; margin-bottom: 16px; box-shadow: var(--shadow-sm); display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
.toolbar .search { flex: 1 1 260px; min-width: 220px; }
.search { position: relative; }
.search input { width: 100%; height: 32px; padding: 0 12px 0 32px; border: 1px solid var(--border-strong); border-radius: 2px; font: inherit; background: var(--surface); }
.search input:focus { outline: 2px solid var(--primary); outline-offset: -2px; border-color: var(--primary); }
.search::before { content: ""; position: absolute; left: 10px; top: 50%; transform: translateY(-50%); width: 14px; height: 14px; background: no-repeat center/contain url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='%23605e5c'><path d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0'/></svg>"); }
.chip-group { display:inline-flex; gap: 4px; }
.chip { display:inline-flex; align-items:center; gap:6px; height: 28px; padding: 0 10px; border-radius: 14px; border: 1px solid var(--border-strong); background: var(--surface); font-size: 12px; cursor: pointer; user-select: none; color: var(--text); }
.chip:hover { background: var(--surface-2); }
.chip.on { background: var(--primary); color:#fff; border-color: var(--primary); }
.chip .dot { width:8px; height:8px; border-radius: 50%; background: currentColor; opacity: .85; }
.toolbar select { height: 32px; padding: 0 8px; border: 1px solid var(--border-strong); border-radius: 2px; background: var(--surface); font: inherit; }
.switch { display:inline-flex; align-items:center; gap: 8px; font-size: 12px; color: var(--text-secondary); }
.switch input { accent-color: var(--primary); }

/* scroll-margin-top accounts for the combined height of the sticky
   app-header and sticky toolbar so that in-page #area-... anchor jumps from
   the sidebar do not hide the area heading behind them. The actual value is
   updated at runtime by JS (--sticky-offset) because the toolbar height
   varies with viewport width (chip / dropdown wrapping) and density toggle.
   The 150px fallback is a safe upper bound used before JS runs. */
.area { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 16px; box-shadow: var(--shadow-sm); overflow: hidden; scroll-margin-top: var(--sticky-offset, 150px); }
.area-head { display:flex; align-items:center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--border); background: var(--surface); }
.area-head h2 { margin: 0; font-size: 15px; font-weight: 600; flex: 1; }
.area-head .pill { font-size: 11px; color: var(--text-secondary); background: var(--surface-2); padding: 2px 8px; border-radius: 10px; }

.check { border-top: 1px solid var(--border); }
.check:first-child { border-top: 0; }
.check-head { display:grid; grid-template-columns: 28px 1fr auto auto; gap: 12px; align-items: center; padding: 12px 16px; cursor: pointer; user-select: none; }
.check-head:hover { background: var(--surface-2); }
.status-dot { width: 10px; height: 10px; border-radius: 50%; justify-self: center; }
.status-ok { background: var(--success); }
.status-rec { background: var(--warning); }
.status-info { background: var(--primary); }
.check-title { font-weight: 600; font-size: 14px; }
.check-meta { color: var(--text-secondary); font-size: 12px; margin-top: 2px; }
.badge { display:inline-flex; align-items:center; gap:4px; font-size: 11px; padding: 2px 8px; border-radius: 10px; line-height: 1.4; }
.badge-ok { background: var(--success-bg); color: var(--success); }
.badge-rec { background: var(--warning-bg); color: var(--warning); }
.badge-info { background: var(--primary-bg); color: var(--primary); }
.chev { color: var(--text-tertiary); transition: transform .15s ease; }
.check.open .chev { transform: rotate(90deg); }
.check-body { display: none; padding: 4px 16px 16px; }
.check.open .check-body { display: block; }

.desc { color: var(--text-secondary); margin: 4px 0 12px; font-size: 13px; }

.tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius); }
table.t { width: 100%; border-collapse: collapse; font-size: 13px; }
table.t th, table.t td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
table.t thead th { background: var(--surface-2); font-weight: 600; font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: .3px; cursor: pointer; user-select: none; white-space: nowrap; }
table.t thead th .sort { color: var(--text-tertiary); margin-left: 4px; font-size: 10px; }
table.t thead th.asc .sort::after { content: "▲"; color: var(--primary); }
table.t thead th.desc .sort::after { content: "▼"; color: var(--primary); }
table.t tbody tr:hover { background: var(--surface-2); }
.pill { display: inline-flex; align-items:center; gap: 4px; font-size: 11px; padding: 2px 8px; border-radius: 10px; margin-right: 4px; background: var(--info-bg); color: var(--info); }
.pill-disabled { background: var(--info-bg); color: var(--text-secondary); }
.pill-readonly { background: var(--primary-bg); color: var(--primary); }
.pill-wontapply { background: var(--info-bg); color: var(--text-secondary); }
.pill-level { background: var(--surface-2); color: var(--text); border: 1px solid var(--border); }

.empty { padding: 40px; text-align: center; color: var(--text-secondary); }

.links { margin-top: 12px; }
.links a { color: var(--primary); text-decoration: none; font-size: 13px; }
.links a:hover { text-decoration: underline; }
.links li { margin: 4px 0; }

.chi-block { margin-top: 4px; }
.chi-row { display: grid; grid-template-columns: 1fr auto; gap: 16px; align-items: center; margin-top: 6px; }
.chi-bar-wrap { position: relative; height: 36px; border-radius: 4px; overflow: hidden; background: var(--surface-2); border: 1px solid var(--border); }
.chi-bar-fill { position: absolute; left:0; top:0; bottom:0; background-image: linear-gradient(135deg, rgba(255,255,255,.18) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.18) 50%, rgba(255,255,255,.18) 75%, transparent 75%, transparent); background-size: 16px 16px; background-color: var(--primary); transition: width .6s ease, background-color .3s ease; width: 0%; }
.chi-bar-label { position: absolute; inset: 0; display:flex; align-items:center; justify-content:center; color: #fff; font-weight: 600; font-size: 18px; text-shadow: 0 1px 2px rgba(0,0,0,.25); }
.chi-desc { color: var(--text-secondary); font-size: 13px; margin-top: 8px; }
.chi-desc a { color: var(--primary); text-decoration: none; }
.chi-desc a:hover { text-decoration: underline; }
.chi-value-large { font-size: 36px; font-weight: 600; color: var(--text); line-height: 1; }
.chi-value-large small { font-size: 13px; color: var(--text-secondary); font-weight: 400; display:block; text-transform: uppercase; letter-spacing: .5px; margin-top: 4px; }

.trend-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 20px; margin-bottom: 16px; box-shadow: var(--shadow-sm); }
.trend-head { display:flex; align-items:baseline; justify-content: space-between; margin-bottom: 8px; }
.trend-head h3 { margin: 0; font-size: 14px; font-weight: 600; }
.trend-head .sub { font-size: 12px; color: var(--text-secondary); }
.trend-canvas-wrap { position: relative; height: 180px; }


.rec-callout { display: flex; align-items: flex-start; gap: 12px; padding: 12px 14px; border-radius: var(--radius); border: 1px solid var(--border); border-left: 4px solid var(--border-strong); background: var(--surface); margin: 4px 0 14px; }
.rec-callout-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .4px; padding: 3px 9px; border-radius: 10px; flex-shrink: 0; line-height: 1.2; align-self: center; }
.rec-callout-text { font-size: 14px; font-weight: 600; color: var(--text); line-height: 1.4; flex: 1; align-self: center; }
.rec-callout.callout-rec  { border-left-color: var(--warning); background: #fff8f5; }
.rec-callout.callout-rec  .rec-callout-label { background: var(--warning-bg); color: var(--warning); }
.rec-callout.callout-ok   { border-left-color: var(--success); background: #f4faf4; }
.rec-callout.callout-ok   .rec-callout-label { background: var(--success-bg); color: var(--success); }
.rec-callout.callout-info { border-left-color: var(--primary); background: #f5fafd; }
.rec-callout.callout-info .rec-callout-label { background: var(--primary-bg); color: var(--primary); }
body.density-compact .rec-callout { padding: 8px 12px; gap: 10px; margin: 2px 0 10px; }
body.density-compact .rec-callout-text { font-size: 13px; }

@media (max-width: 900px) {
    .layout { grid-template-columns: 1fr; }
    .sidebar { display: none; }
    .hero { grid-template-columns: 1fr; }
    .check-head { grid-template-columns: 28px 1fr auto; }
}
'@

        # ---- Client-side render JS (verbatim from the mockup, with three surgical
        # ---- edits: ORCAResult enum mapping, level text comes from server (LevelText),
        # ---- and trend wires up to DATA.HistoricData instead of synthesising points).
        $RenderJs = @'
const DATA = JSON.parse(document.getElementById('report-data').textContent);

// ORCAResult enum: 0=None, 1=Pass, 2=Informational, 3=Fail (matches PowerShell-side cast).
function rowStatus(row, useStrict) {
    const r = useStrict ? row.ResultStrict : row.ResultStandard;
    if (r === 1) return 'ok';
    if (r === 2) return 'info';
    if (r === 3) return 'rec';
    return 'na';
}
function checkStatus(check, useStrict) {
    const r = useStrict ? check.ResultStrict : check.ResultStandard;
    if (r === 1) return 'ok';
    if (r === 2) return 'info';
    return 'rec';
}
// Level text is computed server-side as ORCAConfigLevel.ToString() and travels on each Config row.
function levelText(row) { return (row && row.LevelText) || 'Not Rated'; }
function statusBadge(s) {
    const map = {ok:['badge-ok','OK'], rec:['badge-rec','Recommend'], info:['badge-info','Info']};
    const [cls,lbl] = map[s] || map.rec;
    return `<span class="badge ${cls}">${lbl}</span>`;
}
function statusDot(s) { return `<span class="status-dot status-${s}"></span>`; }
function subsectionAnchorId(area, subsection) {
    return `sub-${encodeURIComponent(area)}-${encodeURIComponent(subsection)}`;
}
function pillsFor(row) {
    const out = [];
    if (row.ConfigDisabled)  out.push(`<span class="pill pill-disabled">Disabled</span>`);
    if (row.ConfigWontApply) out.push(`<span class="pill pill-wontapply">Does not apply</span>`);
    if (row.ConfigReadonly)  out.push(`<span class="pill pill-readonly">Read-only</span>`);
    if (row.InfoText && /Built-In|Built-in/.test(row.InfoText)) out.push(`<span class="pill pill-readonly">Built-in policy</span>`);
    if (row.InfoText && /preset.*Standard/i.test(row.InfoText)) out.push(`<span class="pill pill-readonly">Preset Standard</span>`);
    if (row.InfoText && /preset.*Strict/i.test(row.InfoText))   out.push(`<span class="pill pill-readonly">Preset Strict</span>`);
    return out.join('');
}
function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]);
}

// Header
document.getElementById('hdr-tenant').textContent = DATA.TenantDomain || '—';
document.getElementById('hdr-date').textContent   = DATA.ReportDate || '—';
document.getElementById('hdr-ver').textContent    = DATA.Version || '—';
document.getElementById('tenant-line').textContent = `${DATA.TenantDomain || ''} · ${DATA.ReportDate || ''}`;
const rhT = document.getElementById('rh-tenant'); if (rhT) rhT.textContent = DATA.TenantDomain || '—';
const rhD = document.getElementById('rh-date');   if (rhD) rhD.textContent = DATA.ReportDate || '—';
const rhV = document.getElementById('rh-ver');    if (rhV) rhV.textContent = DATA.Version || '—';

document.getElementById('s-rec').textContent   = DATA.Summary?.Recommendation ?? 0;
document.getElementById('s-ok').textContent    = DATA.Summary?.OK ?? 0;
document.getElementById('s-info').textContent  = DATA.Summary?.InfoCount ?? 0;
document.getElementById('s-total').textContent = (DATA.Checks || []).length;

// CHI bar (server-supplied numeric percentage on DATA.CHI).
const chi = DATA.CHI ?? 0;
document.getElementById('chi-val').textContent = chi + '%';
const fill = document.getElementById('chi-bar-fill');
const fillLabel = document.getElementById('chi-bar-label');
fill.style.width = chi + '%';
fillLabel.textContent = chi + ' %';
fill.style.backgroundColor = chi >= 80 ? 'var(--success)' : chi >= 50 ? 'var(--warning)' : 'var(--danger)';

// Trend chart — wired to DATA.HistoricData when present (server-built from prior
// reports plus current). Falls back to a single-point chart if there is no history.
(function renderTrend() {
    const hist = Array.isArray(DATA.HistoricData) ? DATA.HistoricData : [];
    const labels = hist.map(h => {
        try { return new Date(h.ReportDate).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }); }
        catch { return h.ReportDate || ''; }
    });
    const rec  = hist.map(h => h.Rec  ?? 0);
    const ok   = hist.map(h => h.OK   ?? 0);
    const info = hist.map(h => h.Info ?? 0);

    const ctx = document.getElementById('trendChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: { labels, datasets: [
            { label: 'Recommendations', data: rec,  borderColor: '#ca5010', backgroundColor: 'rgba(202,80,16,.12)', tension: .3, fill: false, borderWidth: 2, pointRadius: 2, pointHoverRadius: 4 },
            { label: 'OK',              data: ok,   borderColor: '#107c10', backgroundColor: 'rgba(16,124,16,.12)', tension: .3, fill: false, borderWidth: 2, pointRadius: 2, pointHoverRadius: 4 },
            { label: 'Informational',   data: info, borderColor: '#0078d4', backgroundColor: 'rgba(0,120,212,.12)', tension: .3, fill: false, borderWidth: 2, pointRadius: 2, pointHoverRadius: 4 }
        ]},
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, boxHeight: 10, font: { family: 'Segoe UI Variable, Segoe UI' } } } },
            scales: {
                x: { grid: { display: false }, ticks: { font: { family: 'Segoe UI Variable, Segoe UI' } } },
                y: { beginAtZero: true, grid: { color: '#f3f2f1' }, ticks: { font: { family: 'Segoe UI Variable, Segoe UI' } } }
            }
        }
    });
    const sub = document.getElementById('trend-sub');
    if (sub) {
        sub.textContent = (DATA.HistoricCount > 1)
            ? `Recommendations, OK, and Informational across ${DATA.HistoricCount} reports`
            : 'Recommendations, OK, and Informational — first report for this tenant, more history will appear on subsequent runs';
    }
})();

// Build area list and collect MDO subsections for sidebar + filter.
// MDO subsections that are exposed as filterable child entries in the sidebar
// and as an optgroup in the area filter dropdown.
const MDO_AREA = 'Microsoft Defender for Office 365 Policies';
const MDO_SUB_ORDER = ['Anti-phishing policy','Safe Attachments policy','Safe Links policy','Priority Account Protection','User reported settings'];
const areas = {};
for (const c of DATA.Checks) {
    if (c.SkipInReport) continue;
    (areas[c.Area] ||= []).push(c);
}
const areaNames = Object.keys(areas).sort();

// Collect which MDO subsections actually have checks, in display order.
const mdoSubs = MDO_SUB_ORDER.filter(sub =>
    (areas[MDO_AREA] || []).some(c => c.Subsection === sub)
);

const navEl = document.getElementById('nav');
const areaFilterEl = document.getElementById('area-filter');

// Build sidebar nav and area filter dropdown, with MDO subsections nested.
for (const a of areaNames) {
    // Top-level sidebar link.
    const ln = document.createElement('a');
    ln.href = `#area-${encodeURIComponent(a)}`;
    ln.dataset.area = a;
    ln.innerHTML = `<span>${escapeHtml(a)}</span><span class="count">${areas[a].length}</span>`;
    navEl.appendChild(ln);

    // If this is the MDO area, inject sub-nav links for each subsection.
    if (a === MDO_AREA && mdoSubs.length) {
        for (const sub of mdoSubs) {
            const subCount = (areas[MDO_AREA] || []).filter(c => c.Subsection === sub).length;
            const sl = document.createElement('a');
            sl.href = `#${subsectionAnchorId(MDO_AREA, sub)}`;
            sl.className = 'sub-nav';
            sl.dataset.area = MDO_AREA;
            sl.dataset.subsection = sub;
            sl.innerHTML = `<span>${escapeHtml(sub)}</span><span class="count">${subCount}</span>`;
            navEl.appendChild(sl);
        }
    }

    // Area filter dropdown — MDO gets an optgroup with sub-options,
    // all other areas get a plain <option>.
    if (a === MDO_AREA && mdoSubs.length) {
        const opt = document.createElement('option');
        opt.value = a; opt.textContent = a;
        areaFilterEl.appendChild(opt);
        const grp = document.createElement('optgroup');
        grp.label = '  ' + a + ' — subsections';
        for (const sub of mdoSubs) {
            const subOpt = document.createElement('option');
            // Prefix with sub:: to distinguish from area names in onChange handler.
            subOpt.value = 'sub::' + sub;
            subOpt.textContent = '    ' + sub;
            grp.appendChild(subOpt);
        }
        areaFilterEl.appendChild(grp);
    } else {
        const opt = document.createElement('option');
        opt.value = a; opt.textContent = a;
        areaFilterEl.appendChild(opt);
    }
}

const state = { q:'', status:'all', area:'', subsection:'', strict:false, onlyApplies:false };

function render() {
    const root = document.getElementById('results');
    root.innerHTML = '';
    const q = state.q.trim().toLowerCase();
    let shown = 0;

    for (const a of areaNames) {
        if (state.area && state.area !== a) continue;
        let checks = areas[a].filter(c => {
            const s = checkStatus(c, state.strict);
            if (state.status !== 'all' && state.status !== s) return false;
            if (q) {
                const hay = (c.Name + ' ' + c.Area + ' ' + (c.Importance||'') + ' ' + (JSON.stringify(c.Config)||'')).toLowerCase();
                if (!hay.includes(q)) return false;
            }
            // When a subsection filter is active restrict to checks in that subsection.
            if (state.subsection && c.Area === MDO_AREA && c.Subsection !== state.subsection) return false;
            return true;
        });
        if (!checks.length) continue;

        const areaEl = document.createElement('section');
        areaEl.className = 'area';
        areaEl.id = `area-${encodeURIComponent(a)}`;
        areaEl.innerHTML = `
            <header class="area-head">
                <h2>${escapeHtml(a)}</h2>
                <span class="pill">${checks.length} check${checks.length>1?'s':''}</span>
            </header>
            <div class="area-body"></div>`;
        const body = areaEl.querySelector('.area-body');

        const hasSub = checks.some(c => c.Subsection);
        const groups = [];
        if (hasSub) {
            const order = ['Anti-phishing policy','Safe Attachments policy','Safe Links policy','Priority Account Protection','User reported settings'];
            const byKey = new Map();
            for (const c of checks) {
                const raw = c.Subsection;
                const keys = Array.isArray(raw) ? raw : (raw ? [raw] : ['__other']);
                for (const k of keys) {
                    if (!byKey.has(k)) byKey.set(k, []);
                    byKey.get(k).push(c);
                }
            }
            for (const k of order) if (byKey.has(k)) groups.push([k, byKey.get(k)]);
            for (const [k, arr] of byKey) {
                if (!order.includes(k) && k !== '__other') groups.push([k, arr]);
            }
            if (byKey.has('__other')) groups.push(['Other', byKey.get('__other')]);
        } else {
            groups.push([null, checks]);
        }

        for (const [subName, subChecks] of groups) {
            const visible = subChecks;
            if (!visible.length) continue;
            if (subName) {
                const sh = document.createElement('div');
                sh.className = 'subsection-head';
                if (a === MDO_AREA) sh.id = subsectionAnchorId(a, subName);
                sh.innerHTML = `<h3>${escapeHtml(subName)}</h3><span class="sub-count">${visible.length} check${visible.length>1?'s':''}</span>`;
                body.appendChild(sh);
            }
            for (const c of visible) {
                const s = checkStatus(c, state.strict);
                const checkEl = document.createElement('div');
                checkEl.className = 'check';
                checkEl.innerHTML = `
                    <div class="check-head">
                        ${statusDot(s)}
                        <div>
                            <div class="check-title">${escapeHtml(c.Name)}</div>
                            <div class="check-meta">${escapeHtml(c.Importance || '').slice(0,180)}${(c.Importance||'').length>180?'…':''}</div>
                        </div>
                        ${statusBadge(s)}
                        <span class="chev">▶</span>
                    </div>
                    <div class="check-body"></div>`;
                const headEl = checkEl.querySelector('.check-head');
                headEl.addEventListener('click', () => {
                    checkEl.classList.toggle('open');
                    if (checkEl.classList.contains('open') && !checkEl.dataset.rendered) {
                        renderCheckBody(checkEl.querySelector('.check-body'), c);
                        checkEl.dataset.rendered = '1';
                    }
                });
                body.appendChild(checkEl);
            }
        }
        root.appendChild(areaEl);
        shown += checks.length;
    }
    if (!shown) root.innerHTML = `<div class="empty">No checks match the current filters.</div>`;
}

function renderCheckBody(el, c) {
    let html = '';

    // Headline recommendation callout. For Pass checks we surface PassText
    // ("...is X"); for everything else we surface FailRecommendation ("Set ... to X"),
    // which is the action-oriented sentence each check defines.
    const cs = checkStatus(c, state.strict);
    const recText = (cs === 'ok' && c.PassText) ? c.PassText : c.FailRecommendation;
    if (recText) {
        const calloutCls = cs === 'ok' ? 'callout-ok' : cs === 'info' ? 'callout-info' : 'callout-rec';
        const calloutLbl = cs === 'ok' ? 'OK' : cs === 'info' ? 'Informational' : 'Recommendation';
        html += `<div class="rec-callout ${calloutCls}">
            <span class="rec-callout-label">${calloutLbl}</span>
            <span class="rec-callout-text">${escapeHtml(recText)}</span>
        </div>`;
    }

    if (c.Importance) html += `<div class="desc">${escapeHtml(c.Importance)}</div>`;

    const rows = (c.Config || []).filter(r => {
        if (state.onlyApplies && (r.ConfigDisabled || r.ConfigWontApply)) return false;
        return true;
    });

    if (rows.length) {
        html += `<div class="tbl-wrap"><table class="t" data-check="${escapeHtml(c.Name)}">
            <thead><tr>
                <th data-k="Object">${escapeHtml(c.ObjectType || 'Policy')} <span class="sort"></span></th>
                <th data-k="ConfigItem">${escapeHtml(c.ItemName || 'Item')} <span class="sort"></span></th>
                <th data-k="ConfigData">${escapeHtml(c.DataType || 'Value')} <span class="sort"></span></th>
                <th data-k="Level">Assessment <span class="sort"></span></th>
                <th data-k="Status">Status <span class="sort"></span></th>
            </tr></thead><tbody>`;
        for (const r of rows) {
            const s = rowStatus(r, state.strict);
            html += `<tr data-status="${s}">
                <td>${escapeHtml(r.Object ?? r.ConfigPolicyGuid ?? '—')}</td>
                <td>${escapeHtml(r.ConfigItem ?? '—')}</td>
                <td>${escapeHtml(r.ConfigData ?? '—')}</td>
                <td><span class="pill pill-level">${escapeHtml(levelText(r))}</span>${pillsFor(r)}</td>
                <td>${statusBadge(s==='na'?'info':s)}</td>
            </tr>`;
        }
        html += `</tbody></table></div>`;
    }

    if (c.Links && Object.keys(c.Links).length) {
        html += `<div class="links"><ul>`;
        for (const k of Object.keys(c.Links)) {
            html += `<li><a href="${escapeHtml(c.Links[k])}" target="_blank" rel="noopener">${escapeHtml(k)}</a></li>`;
        }
        html += `</ul></div>`;
    }
    el.innerHTML = html;

    el.querySelectorAll('table.t thead th').forEach((th, idx) => {
        th.addEventListener('click', () => {
            const tbl = th.closest('table');
            const tbody = tbl.querySelector('tbody');
            const dir = th.classList.contains('asc') ? 'desc' : 'asc';
            tbl.querySelectorAll('th').forEach(h=>h.classList.remove('asc','desc'));
            th.classList.add(dir);
            const rs = [...tbody.querySelectorAll('tr')];
            rs.sort((a,b) => {
                const av = a.children[idx].textContent.trim();
                const bv = b.children[idx].textContent.trim();
                const an = parseFloat(av), bn = parseFloat(bv);
                if (!isNaN(an) && !isNaN(bn)) return dir==='asc' ? an-bn : bn-an;
                return dir==='asc' ? av.localeCompare(bv) : bv.localeCompare(av);
            });
            rs.forEach(r => tbody.appendChild(r));
        });
    });
}

// Wire toolbar
document.getElementById('q').addEventListener('input', e => { state.q = e.target.value; render(); });
document.querySelectorAll('#status-chips .chip').forEach(c => {
    c.addEventListener('click', () => {
        document.querySelectorAll('#status-chips .chip').forEach(x=>x.classList.remove('on'));
        c.classList.add('on'); state.status = c.dataset.status; render();
    });
});
document.getElementById('area-filter').addEventListener('change', e => {
    const val = e.target.value;
    if (val.startsWith('sub::')) {
        // Subsection option selected: restrict to MDO area + that subsection.
        state.area = MDO_AREA;
        state.subsection = val.slice(5);
    } else {
        state.area = val;
        state.subsection = '';
    }
    // Sync sidebar active state.
    navEl.querySelectorAll('a').forEach(x => {
        if (state.subsection) {
            x.classList.toggle('active', x.dataset.subsection === state.subsection);
        } else {
            x.classList.toggle('active', !x.dataset.subsection && x.dataset.area === state.area);
        }
    });
    render();
});

document.getElementById('only-applies').addEventListener('change', e => { state.onlyApplies = e.target.checked; render(); });

navEl.addEventListener('click', e => {
    const a = e.target.closest('a'); if (!a) return;
    navEl.querySelectorAll('a').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    // Sidebar click is navigation-only (do not mutate area/subsection filters).
    // Filters are controlled exclusively by the top toolbar dropdown/chips.
});

// Sidebar collapse — persisted per browser.
const SB_KEY = 'orca-sidebar-collapsed';
if (localStorage.getItem(SB_KEY) === '1') document.body.classList.add('sb-collapsed');
document.getElementById('sb-toggle').addEventListener('click', () => {
    document.body.classList.toggle('sb-collapsed');
    localStorage.setItem(SB_KEY, document.body.classList.contains('sb-collapsed') ? '1' : '0');
    window.dispatchEvent(new Event('resize'));
});

// Density toggle — default compact, persisted per browser.
const D_KEY = 'orca-density';
const initialDensity = localStorage.getItem(D_KEY) || 'compact';
if (initialDensity === 'compact') document.body.classList.add('density-compact');
const densityToggle = document.getElementById('density-toggle');
if (densityToggle) {
    densityToggle.checked = (initialDensity === 'compact');
    densityToggle.addEventListener('change', e => {
        document.body.classList.toggle('density-compact', e.target.checked);
        localStorage.setItem(D_KEY, e.target.checked ? 'compact' : 'comfortable');
        window.dispatchEvent(new Event('resize'));
    });
}

// Sticky-offset measurement: keep --sticky-offset in sync with the actual
// rendered height of the sticky app-header + toolbar so that sidebar anchor
// jumps land the area heading just below the toolbar, not behind it. Both
// elements can change height at runtime (viewport wrap, density toggle), so
// we observe them with ResizeObserver and recompute. An 8px buffer is added
// so the heading is not flush against the toolbar bottom border.
(() => {
    const header = document.querySelector('.app-header');
    const toolbar = document.getElementById('toolbar');
    if (!header || !toolbar) return;
    const updateOffset = () => {
        const h = (header.offsetHeight || 0) + (toolbar.offsetHeight || 0) + 8;
        document.documentElement.style.setProperty('--sticky-offset', h + 'px');
    };
    updateOffset();
    if ('ResizeObserver' in window) {
        const ro = new ResizeObserver(updateOffset);
        ro.observe(header);
        ro.observe(toolbar);
    } else {
        window.addEventListener('resize', updateOffset);
    }
})();

render();
'@

        # ---- Assemble the final document --------------------------------------------
        # Lines 1-2 MUST stay as the checkjson header so GetHistoricData (and any
        # external tooling that parses it) keeps working unchanged.
        $output  = "<!-- checkjson`n"
        $output += $EncodedText
        $output += "`nendcheckjson -->`n"

        $output += @"
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>ORCA Report - $TenantDomain</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
$Css
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
</head>
<body>
<header class="app-header">
    <div class="app-header-inner">
        <div class="brand">
            <span class="brand-mark"><span></span><span></span><span></span><span></span></span>
            <span><span class="brand-product">Defender for Office 365</span><span class="brand-sub">&middot; ORCA Report</span></span>
        </div>
        <div class="header-spacer"></div>
        <div class="header-meta">
            <span><b id="hdr-tenant">&mdash;</b></span>
            <span>Generated <b id="hdr-date">&mdash;</b></span>
            <span>ORCA <b id="hdr-ver">&mdash;</b></span>
        </div>
    </div>
</header>

<div class="layout">
    <aside class="sidebar">
        <div class="sidebar-title">Get started</div>
        <a href="#user-guide" id="nav-guide">README &amp; user guide</a>
        <div class="sidebar-title" style="margin-top:16px">Areas</div>
        <nav id="nav"></nav>
    </aside>
    <button class="sb-toggle" id="sb-toggle" title="Toggle sidebar" aria-label="Toggle sidebar"><span class="chev">&lsaquo;</span></button>

    <main class="main">
        $AlertHtml
        <section class="report-cover">
            <div class="rh-main">
                <h1 class="rh-title">Microsoft Defender for Office 365</h1>
                <div class="rh-subtitle">Recommended Configuration Analyzer report</div>
                <div class="rh-meta">
                    <span>Tenant: <b id="rh-tenant">&mdash;</b></span>
                    <span>Generated: <b id="rh-date">&mdash;</b></span>
                    <span>ORCA <b id="rh-ver">&mdash;</b></span>
                </div>
            </div>
$SurveyHtml
        </section>
        <section class="report-intro">
            <p class="rh-intro">
                ORCA compares your Microsoft Defender for Office 365 configuration against Microsoft&rsquo;s Standard and Strict preset security baselines and reports where your tenant meets the recommended posture, where to improve, and why each setting matters. Use it to prioritize tenant hardening, share status with your team, and track configuration drift over time.
            </p>
        </section>

        <!-- ============================================================== -->
        <!-- README / user guide. Default expanded so first-time readers see -->
        <!-- the orientation; collapsible via the native <details> widget.   -->
        <!-- ============================================================== -->
        <details class="user-guide" id="user-guide">
            <summary>
                <span class="ug-badge">README</span>
                <span>How to read this report &mdash; user guide</span>
                <span class="ug-hint">click to expand</span>
            </summary>
            <div class="ug-body">

                <h3>1. What this report is</h3>
                <p>ORCA (Office 365 Recommended Configuration Analyzer) is a read-only assessment that inspects your Microsoft Defender for Office 365 (MDO) and Exchange Online Protection (EOP) configuration and evaluates settings against Microsoft&rsquo;s recommended security posture, including <b>Standard</b> and <b>Strict</b> preset baseline guidance where applicable.</p>
                <p>The report tells you three things for every setting it checks:</p>
                <ul>
                    <li><b>Where you are</b> &mdash; your current tenant value.</li>
                    <li><b>Where Microsoft recommends you should be</b> &mdash; the baseline value.</li>
                    <li><b>Why it matters</b> &mdash; the security rationale and impact if it is left misconfigured.</li>
                </ul>
                <div class="ug-callout"><b>Important.</b> ORCA does <b>not</b> change anything in your tenant. It is a point-in-time snapshot. Re-run <code>Get-ORCAReport</code> after you make changes to see updated results.</div>

                <h3>2. How the report is organized</h3>
                <p>The report is a single self-contained HTML file. Top to bottom you will find:</p>
                <div class="ug-grid">
                    <div class="ug-card"><b>Cover &amp; intro</b><span>Tenant, generation date, ORCA version, and a one-line description of the report&rsquo;s purpose.</span></div>
                    <div class="ug-card"><b>Summary</b><span>Headline counters for Recommendations, OK, Informational and Total checks, plus the Configuration Health Index.</span></div>
                    <div class="ug-card"><b>Configuration trend</b><span>Historical chart of past report runs so you can see drift and progress over time.</span></div>
                    <div class="ug-card"><b>Toolbar &amp; filters</b><span>Search, status chips, area filter, hide non-applied, and compact density.</span></div>
                    <div class="ug-card"><b>Check cards</b><span>Grouped by Area (e.g. Anti-Spam, Anti-Phishing, Safe Links). Each card shows the verdict, the recommendation, importance, configuration table and useful links.</span></div>
                    <div class="ug-card"><b>Areas sidebar</b><span>Left-pane jump links to any area. Use it for navigation in large tenants.</span></div>
                </div>

                <h3>3. The Summary block</h3>
                <p>The summary shows four counters that classify every check in the report:</p>
                <ul>
                    <li><span class="ug-pill rec">Recommendations</span> Checks where at least one configuration item does <b>not</b> meet the baseline. These are the items to act on.</li>
                    <li><span class="ug-pill ok">OK</span> Checks where every inspected item meets the baseline. Nothing to do.</li>
                    <li><span class="ug-pill info">Informational</span> Checks that surface useful context but are not pass/fail (e.g. tenant version checks, presence of certain policies). Review for awareness.</li>
                    <li><b>Total checks</b> The full count of checks ORCA executed for your tenant.</li>
                </ul>

                <h3>4. Configuration Health Index (CHI)</h3>
                <p>The <b>Configuration Health Index</b> is a single weighted score that summarizes how close your tenant is to Microsoft&rsquo;s recommended posture. Higher is better.</p>
                <ul>
                    <li>Not every check is included &mdash; only those that meaningfully affect protection posture contribute to the score.</li>
                    <li>Checks are <b>weighted</b>: high-impact protections (e.g. impersonation, Safe Links) count for more than lower-impact ones.</li>
                    <li>Track the CHI trend over time. A rising CHI shows your hardening work is paying off; a falling CHI indicates configuration drift.</li>
                </ul>
                <p>The historical CHI is plotted in the <b>Configuration trend</b> chart next to the summary block whenever previous reports are available on the same machine.</p>

                <h3>5. Reading an individual check</h3>
                <p>Click any check card to expand it. Inside you will see:</p>
                <ul>
                    <li><b>Recommendation line</b> at the top &mdash; the specific change Microsoft recommends (e.g. &ldquo;Set the Bulk Complaint Level threshold to be 6&rdquo;).</li>
                    <li><b>Importance</b> &mdash; the business and security rationale for the setting.</li>
                    <li><b>Configuration table</b> &mdash; every policy / object inspected, its current value, and whether that value passes the baseline. The <b>Object</b>, <b>Property</b> and <b>Current value</b> columns let you go straight to the right policy in the Defender portal. Each row in the table carries an <b>Assessment</b> badge:
                        <ul style="margin-top:6px;">
                            <li><span class="ug-pill ok">Pass</span> The setting meets the recommended baseline for the selected assessment level.</li>
                            <li><span class="ug-pill rec">Fail</span> The setting does not meet the baseline. Action is recommended.</li>
                            <li><span class="ug-pill info">Informational</span> The setting is surfaced for awareness but is not scored as pass or fail (e.g. read-only built-in policies, informational checks).</li>
                            <li><b>Does not apply</b> &mdash; The policy or rule exists in your tenant but has no effective user coverage. This typically means the policy&rsquo;s recipient/domain conditions match no one, or the associated rule is disabled.</li>
                        </ul>
                    </li>
                    <li><b>Links</b> &mdash; jump points to the relevant Microsoft Learn documentation or the Defender portal page.</li>
                </ul>

                <h3>6. Configuration changes &mdash; how to act on a recommendation</h3>
                <ol>
                    <li>Open the check card and read the <b>Recommendation</b> and <b>Importance</b>.</li>
                    <li>Use the <b>Object</b> column to identify which policy or object needs changing (e.g. &ldquo;Default&rdquo; anti-spam policy, a specific custom policy, a connector).</li>
                    <li>Make the change in the <b>Microsoft Defender portal</b> or via Exchange Online PowerShell. ORCA itself never writes to your tenant.</li>
                    <li>Re-run <code>Get-ORCAReport</code> to confirm the check now passes.</li>
                </ol>
                <div class="ug-callout">If a check fails against many policies, fix the <b>Default</b> policy first. It applies to every user who is not explicitly scoped to a custom policy and usually has the largest reach.</div>

                <h3>7. Filters &amp; navigation</h3>
                <p>The toolbar above the check list lets you focus on what matters:</p>
                <ul>
                    <li><b>Search</b> &mdash; matches check name, area, item name, object, property and current value.</li>
                    <li><b>Status chips</b> (All / Recommend / OK / Info) &mdash; toggle visibility by verdict.</li>
                    <li><b>Area filter</b> &mdash; restrict to a single MDO/EOP feature area.</li>
                    <li><b>Hide disabled / non-applied</b> &mdash; suppresses rows for policies that exist but are not applied to any user, plus disabled rules.</li>
                    <li><b>Compact</b> &mdash; tightens spacing for large reports or smaller screens.</li>
                </ul>
                <p>Use the <b>Areas</b> list in the left pane to jump straight to a feature area (Anti-Spam, Anti-Phishing, Safe Links, Safe Attachments, Connectors, Transport Rules, etc.).</p>

                <h3>8. Suggested workflow for a first-time reader</h3>
                <ol>
                    <li>Read the <b>Summary</b> and note the <b>Configuration Health Index</b>.</li>
                    <li>Click the <b>Recommend</b> status chip to filter down to items that need attention.</li>
                    <li>Walk each recommendation card top-to-bottom and create a remediation action list in your preferred tracking system (ticketing / project board).</li>
                    <li>Make the easy / high-impact changes in the Defender portal.</li>
                    <li>Share the report with your team for peer review and change planning.</li>
                    <li>Re-run <code>Get-ORCAReport</code> after the change window to confirm the items have moved to OK.</li>
                </ol>

                <h3>9. Where to get help</h3>
                <ul>
                    <li>Project &amp; issues: <a href="https://aka.ms/orca-github" target="_blank" rel="noopener">aka.ms/orca-github</a></li>
                    <li>Microsoft recommended settings: <a href="https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365" target="_blank" rel="noopener">Recommended settings for EOP and Microsoft Defender for Office 365</a></li>
                    <li>Preset security policies: <a href="https://learn.microsoft.com/defender-office-365/preset-security-policies" target="_blank" rel="noopener">Preset security policies in EOP and Defender for Office 365</a></li>
                </ul>

            </div>
        </details>

        <div class="overview-grid">
            <section class="hero" style="grid-template-columns: 1fr; min-width: 0;">
                <div>
                    <h1>Summary</h1>
                    <div class="tenant" id="tenant-line">&mdash;</div>
                    <div class="hero-stats">
                        <div class="stat rec"><div class="v" id="s-rec">0</div><div class="l">Recommendations</div></div>
                        <div class="stat ok"><div class="v" id="s-ok">0</div><div class="l">OK</div></div>
                        <div class="stat info"><div class="v" id="s-info">0</div><div class="l">Informational</div></div>
                        <div class="stat total"><div class="v" id="s-total">0</div><div class="l">Total checks</div></div>
                    </div>

                    <div class="chi-block">
                        <div class="chi-row">
                            <div>
                                <div style="font-size:12px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Configuration Health Index</div>
                                <div class="chi-bar-wrap">
                                    <div class="chi-bar-fill" id="chi-bar-fill"></div>
                                    <div class="chi-bar-label" id="chi-bar-label">&mdash;</div>
                                </div>
                            </div>
                            <div class="chi-value-large"><span id="chi-val">&mdash;</span><small>weighted score</small></div>
                        </div>
                        <p class="chi-desc">The configuration health index is a weighted value representing your configuration. Not all configuration is considered and some configuration is weighted higher than others. <a href="https://aka.ms/orca-github" target="_blank" rel="noopener">See more</a></p>
                    </div>
                </div>
            </section>

            <section class="trend-card">
                <div class="trend-head">
                    <h3>Configuration trend</h3>
                    <span class="sub" id="trend-sub">Recommendations, OK, and Informational over time</span>
                </div>
                <div class="trend-canvas-wrap"><canvas id="trendChart"></canvas></div>
            </section>
        </div>

        <section class="toolbar" id="toolbar">
            <div class="search"><input id="q" type="search" placeholder="Search checks, items, objects, properties..." /></div>
            <div class="chip-group" id="status-chips">
                <button class="chip on" data-status="all">All</button>
                <button class="chip" data-status="rec"><span class="dot" style="background:var(--warning)"></span>Recommend</button>
                <button class="chip" data-status="ok"><span class="dot" style="background:var(--success)"></span>OK</button>
                <button class="chip" data-status="info"><span class="dot" style="background:var(--primary)"></span>Info</button>
            </div>
            <select id="area-filter"><option value="">All areas</option></select>
            <label class="switch"><input type="checkbox" id="only-applies" /> Hide disabled/non-applied</label>
            <label class="switch"><input type="checkbox" id="density-toggle" /> Compact</label>
        </section>

        <div id="results"></div>
    </main>
</div>

<script id="report-data" type="application/json">$Json</script>
<script>
$RenderJs
</script>
</body>
</html>
"@

        # ---- Write file --------------------------------------------------------------
        $OutputDir      = $this.GetOutputDir()
        $ReportFileName = "ORCA-$Tenant-$(Get-Date -Format 'yyyyMMddHHmm').html"
        $OutputFile     = "$OutputDir\$ReportFileName"

        $output | Out-File -FilePath $OutputFile -Encoding utf8

        if ($this.DisplayReport)
        {
            Invoke-Expression "&'$OutputFile'"
        }

        $this.Completed = $true
        $this.Result    = $OutputFile
    }
}
