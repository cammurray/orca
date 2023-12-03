using module "..\ORCA.psm1"

class html : ORCAOutput
{

    $OutputDirectory=$null
    $DisplayReport=$True
    $EmbedConfiguration=$false

    html()
    {
        $this.Name="HTML"
    }

    RunOutput($Checks,$Collection,[ORCAConfigLevel]$AssessmentLevel)
    {
    <#

        OUTPUT GENERATION / Header

    #>

    # Obtain the tenant domain and date for the report
    $TenantDomain = ($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName
    $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
    $ReportDate = $(Get-Date -format 'dd-MMM-yyyy HH:mm')

    # Summary Where-Object {$_.Completed -eq $true}
    $RecommendationCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Fail -and $_.Completed -eq $true}).Count
    $OKCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Pass -and $_.Completed -eq $true}).Count
    $InfoCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Informational -and $_.Completed -eq $true}).Count

    # Misc
    $ReportTitle = "Microsoft Defender for Office 365 Recommended Configuration Analyzer"
    $ReportSub1 = "Microsoft Defender for Office 365 Recommended"
    $ReportSub2 = "Configuration Analyzer Report"
    # Area icons
    $AreaIcon = @{}
    $AreaIcon["Default"] = "fas fa-user-cog"
    $AreaIcon["Connectors"] = "fas fa-plug"
    $AreaIcon["Anti-Spam Policies"] = "fas fa-trash"
    $AreaIcon["Malware Filter Policy"] = "fas fa-biohazard"
    $AreaIcon["Zero Hour Autopurge"] = "fas fa-trash"
    $AreaIcon["DKIM"] = "fas fa-file-signature"
    $AreaIcon["Transport Rules"] = "fas fa-list"
    $AreaIcon["Transport Rules"] = "fas fa-list"

    # Embed checks as JSON in to HTML file at beginning for charting/historic purposes
    $MetaObject = New-Object -TypeName PSObject -Property @{
        Tenant=$Tenant
        TenantDomain=$TenantDomain
        ReportDate=$ReportDate
        Version=$($this.VersionCheck.Version.ToString())
        Config=$null
        EmbeddedConfiguration=$this.EmbedConfiguration
        Summary=New-Object -TypeName PSObject -Property @{
            Recommendation=$RecommendationCount
            OK=$OKCount
            InfoCount=$InfoCount
        }
        Checks=$Checks
    }

    if($this.EmbedConfiguration -eq $true)
    {
        # Write in to temp file to use clixml
        $TempFileXML = New-TemporaryFile

        # Create the temp path for zip
        $ZipTempLoc = New-TemporaryFile
        $ZipPath = $($ZipTempLoc.ToString()) + ".zip"

        # Export collection to XML file
        $Collection | Export-Clixml -Path $TempFileXML

        # Compress the XML to ZIP
        Compress-Archive -Path $TempFileXML -DestinationPath $ZipPath

        # Store in meta object, on Core use AsByteStream, on other use -Encoding byte
        if($global:PSVersionTable.PSEdition -eq "Core")
        {
            $MetaObject.Config = [convert]::ToBase64String((Get-Content -path $ZipPath -AsByteStream))
        }
        else 
        {
            $MetaObject.Config = [convert]::ToBase64String((Get-Content -path $ZipPath -Encoding byte))
        }
        
        $MetaObject.EmbeddedConfiguration = $true

        # Clean-up paths
        Remove-Item -Path $TempFileXML
        Remove-Item -Path $ZipTempLoc
        Remove-Item -Path $ZipPath
    }

    $EncodedText = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($MetaObject | ConvertTo-Json -Depth 100)))
    $output = "<!-- checkjson`n"
    $output += $($EncodedText)
    $output += "`nendcheckjson -->"

    # Get historic report info
    $HistoricData = $this.GetHistoricData($MetaObject,$Tenant)

    # Output start
    $output += "<!doctype html>
    <html lang='en'>
    <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <script src='https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.7/dist/umd/popper.min.js' integrity='sha384-zYPOMqeu1DAVkHiLqWBUTcbYfZ8osu1Nd6Z89ify25QV9guujx43ITvfi12/QExE' crossorigin='anonymous'></script>

        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css' rel='stylesheet' integrity='sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ' crossorigin='anonymous'>
        <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js' integrity='sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe' crossorigin='anonymous'></script>

        <script src='https://code.jquery.com/jquery-3.3.1.slim.min.js' integrity='sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo' crossorigin='anonymous'></script>
        
        <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/css/all.min.css' crossorigin='anonymous'>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/js/all.js'></script>

        <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
        <script src='https://cdn.jsdelivr.net/npm/moment@2.27.0'></script>
        <script src='https://cdn.jsdelivr.net/npm/chartjs-adapter-moment@0.1.1'></script>
        
        <style>
        .table-borderless td,
        .table-borderless th {
            border: 0;
        }
        .bd-callout {
            padding: 1rem;
            margin-top: 1rem;
            margin-bottom: 1rem;
            border: 1px solid #eee;
            border-left-width: .25rem;
            border-radius: .25rem
        }
        
        .bd-callout h4 {
            margin-top: 0;
            margin-bottom: .25rem
        }
        
        .bd-callout p:last-child {
            margin-bottom: 0
        }
        
        .bd-callout code {
            border-radius: .25rem
        }
        
        .bd-callout+.bd-callout {
            margin-top: -.25rem
        }
        
        .bd-callout-info {
            border-left-color: #5bc0de
        }
        
        .bd-callout-info h4 {
            color: #5bc0de
        }
        
        .bd-callout-warning {
            border-left-color: #f0ad4e
        }
        
        .bd-callout-warning h4 {
            color: #f0ad4e
        }
        
        .bd-callout-danger {
            border-left-color: #d9534f
        }
        
        .bd-callout-danger h4 {
            color: #d9534f
        }

        .bd-callout-success {
            border-left-color: #00bd19
        }

        .navbar-custom { 
            background-color: #005494;
            color: white; 
            padding-bottom: 10px;

            
        } 
        /* Modify brand and text color */ 
          
        .navbar-custom .navbar-brand, 
        .navbar-custom .navbar-text { 
            color: white; 
            padding-top: 70px;
            padding-bottom: 10px;

        } 
        .star-cb-group {
            /* remove inline-block whitespace */
            font-size: 0;
            /* flip the order so we can use the + and ~ combinators */
            unicode-bidi: bidi-override;
            direction: rtl;
            /* the hidden clearer */
          }
          .star-cb-group * {
            font-size: 1rem;
          }
          .star-cb-group > input {
            display: none;
          }
          .star-cb-group > input + label {
            /* only enough room for the star */
            display: inline-block;
            overflow: hidden;
            text-indent: 9999px;
            width: 1.7em;
            white-space: nowrap;
            cursor: pointer;
          }
          .star-cb-group > input + label:before {
            display: inline-block;
            text-indent: -9999px;
            content: ""\2606"";
            font-size: 30px;
            color: #005494;
          }
          .star-cb-group > input:checked ~ label:before, .star-cb-group > input + label:hover ~ label:before, .star-cb-group > input + label:hover:before {
            content:""\2605"";
            color: #e52;
          font-size: 30px;
            text-shadow: 0 0 1px #333;
          }
          .star-cb-group > .star-cb-clear + label {
            text-indent: -9999px;
            width: .5em;
            margin-left: -.5em;
          }
          .star-cb-group > .star-cb-clear + label:before {
            width: .5em;
          }
          .star-cb-group:hover > input + label:before {
            content: ""\2606"";
            color: #005494;
          font-size: 30px;
            text-shadow: none;
          }
          .star-cb-group:hover > input + label:hover ~ label:before, .star-cb-group:hover > input + label:hover:before {
            content: ""\2605"";
            color: #e52;
          font-size: 30px;
            text-shadow: 0 0 1px #333;
          }         
        </style>

        <title>$($ReportTitle)</title>

    </head>
    <body class='app header-fixed bg-light'>

        <nav class='navbar  fixed-top navbar-custom p-3 border-bottom d-print-block'>
            <div class='container-fluid'>
                <div class='col-sm' style='text-align:left'>
                    <div class='row'>
                        <div class='col col-md-auto'><i class='fas fa-binoculars'></i></div>
                        <div class='col'><strong>ORCA</strong></div>
                    </div>
                </div>
                <div class='col-sm' style='text-align:center'>
                    <strong>$($TenantDomain)</strong>
                </div>
                <div class='col-sm' style='text-align:right'>
                    $($ReportDate)
                </div>
            </div>
        </nav>  

            <div class='app-body p-3'>
            <main class='main'>
                <!-- Main content here -->
                <div class='container' style='padding-top:50px;'></div>
                <div class='card'>
                        
                        <div class='card-body'>
                            <h2 class='card-title'>$($ReportSub1)</h2>

                            <div style='text-align:right;margin-top:-10px';>            
                            <span class='star-cb-group'>
                               <input type='radio' id='rating-5' name='rating' value='5' onclick=""window.open('https://aka.ms/orca-feedback-1','_blank');"" />
                               <label for='rating-5'>5</label>
                               <input type='radio' id='rating-4' name='rating' value='4' onclick=""window.open('https://aka.ms/orca-feedback-2','_blank');"" />
                               <label for='rating-4'>4</label>
                               <input type='radio' id='rating-3' name='rating' value='3' onclick=""window.open('https://aka.ms/orca-feedback-3','_blank');"" />
                               <label for='rating-3'>3</label>
                               <input type='radio' id='rating-2' name='rating' value='2' onclick=""window.open('https://aka.ms/orca-feedback-4','_blank');"" />
                               <label for='rating-2'>2</label>
                               <input type='radio' id='rating-1' name='rating' value='1' onclick=""window.open('https://aka.ms/orca-feedback-5','_blank');"" />
                               <label for='rating-1'>1</label>
                               <input type='radio' id='rating-0' name='rating' value='0' class='star-cb-clear' />
                               <label for='rating-0'>0</label>
                               </span>
                            </div>
                            <h2 class='card-title' style='margin-top:-10px'>$($ReportSub2)</h2>

                            <strong>Version $($this.VersionCheck.Version.ToString())</strong>
                            
                            <p>This report details any tenant configuration changes recommended within your tenant.</p>"

        <#

                OUTPUT GENERATION / Version Warning

        #>

        if($this.EmbedConfiguration)
        {
            $Output += "
            <div class='alert alert-warning pt-2' role='alert'>
                <p><strong>Embedded Configuration is present</strong></p>
                <p>This report has embedded configuration in it as ORCA was ran with the -EmbedConfiguration parameter. This allows anyone who holds this report file to view your configuration for the purpose of supporting your organisation, or as a snapshot of your configuration at a point in time. In order to read the configuration in this report, with the ORCA module installed, run Get-ORCAReportEmbeddedConfig -File <path to this .html file>.</p>
                <p>For those holding this report, treat this report file as confidential, and only send this report to people that you trust reading your configuration.</p>
            </div>" 
        }
        
        if($this.VersionCheck.GalleryCheck)
        {
            If($this.VersionCheck.Updated -eq $False) 
            {

                $Output += "
                <div class='alert alert-danger pt-2' role='alert'>
                    ORCA is out of date. You're running version $($this.VersionCheck.Version) but version $($this.VersionCheck.GalleryVersion) is available! Run Update-Module ORCA to get the latest definitions!
                </div>
                
                "
            }
        }
        else
        {
            $Output += "
            <div class='alert alert-info pt-2' role='alert'>
                VersionChecks were disabled when running ORCA. Ensure that you're periodically running Update-Module ORCA to get the latest definitions!
            </div>
            
            "
        }

        If($this.VersionCheck.Preview -eq $True) {

            $Output += "
            <div class='alert alert-warning pt-2' role='alert'>
                You are running a preview version of ORCA! Preview versions may contain errors which could result in an incorrect report. Verify the results and any configuration before deploying changes.
            </div>
            
            "
        }

        If(!($Collection["Services"] -band [ORCAService]::MDO))
        {
            $Output += "
            <div class='alert alert-danger pt-2' role='alert'>
                <p>Microsoft Defender for Office 365 was <strong>NOT</strong> detected on this tenant. <strong>The purpose of ORCA is to check for Microsoft Defender for Office 365 recommended configuration</strong> - <i>however, these checks will be skipped. Other results should be relevant to base EOP configuration.</i></p>
                <p>Consider Microsoft Defender for Office 365 for:<ul><li>Automatic incident response capabilities</li><li>Attack simulation capabilities</li><li>Behavioural analysis (sandboxing) of malware</li><li>Time of click protection against URLs</li><li>Advanced anti-phishing controls</li></ul></p>
            </div>
            
            "    
        }

        if(@($Checks | Where-Object {$_.CheckFailed}).Count -gt 0)
        {
            $Output += "
            <div class='alert alert-danger pt-2' role='alert'>
                <p>Some checks failed to run, check details below for more information</p>
            </div>" 
        }

                        $Output += "</div>
                </div>"

                        $Output += "</div>
                </div>"



    <#

        OUTPUT GENERATION / Summary cards

    #>

    $Output += "

                <div class='row p-3'>"

                if($InfoCount -gt 0)
                {
                    $Output += "
                    
                            <div class='col d-flex justify-content-center text-center'>
                                <div class='card text-white bg-secondary mb-3' style='width: 18em;'>
                                    <div class='card-header'><h6>Informational</h6></div>
                                    <div class='card-body'>
                                    <h3>$($InfoCount)</h3>
                                    </div>
                                </div>
                            </div>
                    
                    "
                }

$Output +=        "<div class='col d-flex justify-content-center text-center'>
                    <div class='card text-white bg-warning mb-3' style='width: 18rem;'>
                        <div class='card-header'><h6>Recommendations</h6></div>
                        <div class='card-body'>
                        <h3>$($RecommendationCount)</h3>
                        </div>
                    </div>
                </div>

                <div class='col d-flex justify-content-center text-center'>
                    <div class='card text-white bg-success mb-3' style='width: 18rem;'>
                        <div class='card-header'><h6>OK</h6></div>
                        <div class='card-body'>
                        <h3>$($OKCount)</h3>
                        </div>
                    </div>
                </div>

                <div>
                    <canvas id='chartOverview' height='80'></canvas>
                </div>

            </div>"

    <#
    
                SURVEY OUTPUT
    
    #>

    if($this.ShowSurvey -eq $true)
    {
            $Output += "
    <div class='card text-white bg-secondary mb-3'>
        <div class='card-header'>ORCA needs your assistance..</div>
        <div class='card-body'>
            <div class='row'>
                <div class='col-md-auto'>
                    <a href='http://aka.ms/orcasurvey'>
                    <img src='data:image/png;base64,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' />
                    </a>
                </div>
                <div class='col'>
                    <h5 class='card-title'>Call for action!</h5>
                    <p class='card-text'>ORCA is a community/garage project and we need to understand how it's being used today. Please fill in the survey by scanning the QR code to the left, clicking on the image, or by visiting the survey link http://aka.ms/orcasurvey</a></p>
                    <p>We don't want to nag -but pretty please fill in the survey-. If you want to stop this message from appearing, you can add -nosurvey when running ORCA.</p>
                </div>
            </div>
        </div>
    </div>"

    }

    <#
    
                OUTPUT GENERATION / Config Health Index

    #>

    $Output += "
    <div class='card m-3'>

        <div class='card-body'>
            <div class='row'>
                <div class='col-sm-4 text-center align-self-center'>

                    <div class='progress' style='height: 40px'>
                        <div class='progress-bar progress-bar-striped bg-info' role='progressbar' style='width: $($Collection["CHI"])%;' aria-valuenow='$($Collection["CHI"])' aria-valuemin='0' aria-valuemax='100'><h2>$($Collection["CHI"]) %</h2></div>
                    </div>
                
                </div>
                <div class='col-sm-8'>
                    <h6>Configuration Health Index</h6>                  
                    <p>The configuration health index is a weighted value representing your configuration. Not all configuration is 
                    considered and some configuration is weighted higher than others.<a href='https://aka.ms/orca-github' target='_blank'> See More </a></p>

                </div>
            </div>
                    
    </div>
  
    
    "

    <#
    
        OUTPUT GENERATION / Summary

    #>

    $Output += "
    <div class='card m-3'>
        <div class='card-header'>
            Summary
        </div>
        <div class='card-body'>"


    $Output += "<h5>Areas</h1>
            <table class='table table-borderless'>"
    ForEach($Area in ($Checks | Where-Object {$_.Completed -eq $true} | Group-Object Area))
    {

        $Pass = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Pass}).Count
        $Fail = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Fail}).Count
        $Info = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Informational}).Count

        $Icon = $AreaIcon[$Area.Name]
        If($Null -eq $Icon) { $Icon = $AreaIcon["Default"]}

        $Output += "
        <tr>
            <td width='20'><i class='$Icon'></i>
            <td><a href='`#$($Area.Name)'>$($Area.Name)</a></td>
            <td align='right'>
                <span class='badge text-bg-secondary' style='padding:15px;text-align:center;width:40px;"; if($Info -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Info)</span>
                <span class='badge text-bg-warning' style='padding:15px;text-align:center;width:40px;"; if($Fail -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Fail)</span>
                <span class='badge text-bg-success' style='padding:15px;text-align:center;width:40px;"; if($Pass -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Pass)</span>
            </td>
        </tr>
        "
    }

    $Output+="</table>
        </div>
    </div>
    "

    <#
    
    Keys
    
    #>

    $Output += "
    <div class='card m-3'>
        <div class='card-header'>
            Legend
        </div>
        <div class='card-body'>
            <table class='table table-borderless'>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-dark'>
                            <span style='vertical-align: middle;'>Disabled</span>
                            <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                        </div>
                    </td>
                    <td>
                        Disabled configuration or disabled policies won't apply due to explicit disablement of the policy or configuration.
                    </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-secondary'>
                            <span style='vertical-align: middle;'>Does not apply</span>
                            <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                        </div>
                    </td>
                    <td>
                        These policies or configuration do not apply due to policy precedence or exceptions on the policy or configuration. An example is a default policy, where there is a preset policy applying with no exceptions.
                    </td>
                </tr>

                <tr>
                <td width='100'>
                    <div class='flex-row badge badge-pill text-bg-light'>
                    <span style='vertical-align: middle;'>Read Only</span>
                    <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                    </div>
                </td>
                <td>
                    Read only policies cannot be modified. In instances where read-only policies contain configuration that you do not want, apply a higher ordered policy so these won't apply.
                </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-info'>
                            <span style='vertical-align: middle;'>Preset Standard/Strict</span>
                        </div>
                    </td>
                    <td>
                        Pre-set policies provide settings that are controlled by Microsoft and configured at a specific level of controls (Standard or Strict), most settings are usually read-only.
                    </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-info'>
                            <span style='vertical-align: middle;'>Built-in Protection Policy</span>
                        </div>
                    </td>
                    <td>
                        Built-in policies apply in the absence of other policies, most settings are usually read-only.
                    </td>
                </tr>
            
                
            </table>
        </div>
    </div>"

    <#

        OUTPUT GENERATION / Zones

    #>

    ForEach ($Area in ($Checks | Where-Object {$_.Completed -eq $True} | Group-Object Area)) 
    {

        # Write the top of the card
        $Output += "
        <div class='card m-3'>
            <div class='card-header'>
            <a name='$($Area.Name)'>$($Area.Name)</a>
            </div>
            <div class='card-body'>"

        # Each check
        ForEach ($Check in ($Area.Group | Sort-Object Result -Descending)) 
        {

            $Output += "        
                <h5>$($Check.Name)</h5>"

                    If($Check.Result -eq [ORCAResult]::Pass) 
                    {
                        $CalloutType = "bd-callout-success"
                        $BadgeType = "text-bg-success"
                        $BadgeName = "OK"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.PassText
                    } 
                    ElseIf($Check.Result -eq [ORCAResult]::Informational) 
                    {
                        $CalloutType = "bd-callout-secondary"
                        $BadgeType = "text-bg-secondary"
                        $BadgeName = "Informational"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.FailRecommendation
                    }
                    Else 
                    {
                        $CalloutType = "bd-callout-warning"
                        $BadgeType = "text-bg-warning"
                        $BadgeName = "Improvement"
                        $Icon = "fas fa-thumbs-down"
                        $Title = $Check.FailRecommendation
                    }

#<span class="badge text-bg-primary">Primary</span>

                    $Output += "  
                    
                        <div class='bd-callout $($CalloutType) b-t-1 b-r-1 b-b-1 p-3'>
                            <div class='container-fluid'>
                                <div class='row'>
                                    <div class='col-1'><i class='$($Icon)'></i></div>
                                    <div class='col-8'><h5>$($Title)</h5></div>
                                    <div class='col' style='text-align:right'><h5><span class='badge $($BadgeType)'>$($BadgeName)</span></h5></div>
                                </div>"


                        if($Check.CheckFailed)
                        {
                                $Output +="
                                <div class='row p-3'>
                                    <div class='alert alert-danger' role='alert'>
                                    This check failed to run.  $($Check.CheckFailureReason)
                                    </div>
                                </div>"
                        }

                        if($Check.Importance) {

                                $Output +="
                                <div class='row p-3'>
                                    <div><p>$($Check.Importance)</p></div>
                                </div>"

                        }

                        If($Check.ExpandResults -eq $True) {

                            # We should expand the results by showing a table of Config Data and Items
                            $Output +="<h6>Effected objects</h6>
                            <div class='row pl-2 pt-3'>
                                <table class='table'>
                                    <thead class='border-bottom'>
                                        <tr>"

                            If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                            {
                                # Object, property, value checks need three columns
                                $Output +="
                                <th>$($Check.ObjectType)</th>
                                <th>$($Check.ItemName)</th>
                                <th>$($Check.DataType)</th>
                                "    
                            }
                            Else
                            {
                                $Output +="
                                <th>$($Check.ItemName)</th>
                                <th>$($Check.DataType)</th>
                                "     
                            }

                            $Output +="
                                            <th style='width:100px'></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                            "

                            ForEach($o in $($Check.Config | Sort-Object Level))
                            {

                                $chiicon = ""
                                $chipill = ""
                                $chipts = [int]$($Check.ChiValue)

                                # Determine which to use based on AssessmentLevel
                                [ORCAResult]$AssessedResult = $o.ResultStandard

                                if($AssessmentLevel -eq [ORCAConfigLevel]::Strict)
                                {
                                    [ORCAResult]$AssessedResult = $o.ResultStrict
                                }
                                
                                if($AssessedResult -eq [ORCAResult]::Pass) 
                                {
                                    $oicon="fas fa-check-circle text-success"
                                    
                                    $LevelText = $o.Level.ToString()

                                    if($Check.ChiValue -ne [ORCACHI]::NotRated)
                                    {
                                        $chiicon = "fas fa-plus"
                                        $chipill = "text-bg-success"
                                    }
                                }
                                ElseIf($AssessedResult -eq [ORCAResult]::Informational) 
                                {
                                    $oicon="fas fa-info-circle text-muted"
                                    $LevelText = "Informational"
                                }
                                Else
                                {
                                    $oicon="fas fa-times-circle text-danger"
                                    $LevelText = "Not Recommended"

                                    if($Check.ChiValue -ne [ORCACHI]::NotRated)
                                    {
                                        $chiicon = "fas fa-minus"
                                        $chipill = "text-bg-danger"
                                    }
                                }

                                $Output += "
                                <tr>
                                "

                                # Multi line ConfigItem or ConfigData
                                If($o.ConfigItem -is [array] -or $o.ConfigItem -is [System.Collections.ArrayList])
                                {
                                    $ConfigItem = $o.ConfigItem -join "<br>"
                                }
                                else 
                                {
                                    $ConfigItem = $o.ConfigItem
                                }
                                If($o.ConfigData -is [array] -or $o.ConfigData -is [System.Collections.ArrayList])
                                {
                                    $ConfigData = $o.ConfigData -join "<br>"
                                }
                                else 
                                {
                                    $ConfigData = $o.ConfigData
                                }

                                $PolicyPills = "";

                                if($null -ne $o.ConfigPolicyGuid)
                                {
                                    # Get policy object
                                    $Policy = $Collection["PolicyStates"][$o.ConfigPolicyGuid]

                                    if($Policy.Preset)
                                    {
                                        $PolicyPills += "
                                            <div class='flex-row badge badge-pill text-bg-info'>
                                                <span style='vertical-align: middle;'>Preset ($($Policy.PresetLevel.ToString()))</span>
                                            </div>"
                                    }

                                    if($Policy.BuiltIn)
                                    {
                                        $PolicyPills += "
                                            <div class='flex-row badge badge-pill text-bg-info'>
                                                <span style='vertical-align: middle;'>Built-in Protection Policy</span>
                                            </div>"
                                    }

                                }

                                If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                                {
                                    # Object, property, value checks need three columns
                                    $Output += "<td>$($o.Object)"

                                    if($o.ConfigDisabled -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-dark'>
                                                    <span style='vertical-align: middle;'>Disabled</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigWontApply -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-secondary'>
                                                    <span style='vertical-align: middle;'>Does not apply</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigReadonly -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>Read Only</span>
                                                    <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }
                                    
                                    $Output += $PolicyPills
                                    
                                    $Output += "</td>"
                                        
                                    $Output += "<td>$($ConfigItem)</td>
                                        <td style='word-wrap: break-word;min-width: 50px;max-width: 350px;'>$($ConfigData)</td>
                                    "
                                }
                                Else 
                                {
                                    $Output += "<td>$($ConfigItem)"

                                    if($o.ConfigDisabled -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-dark'>
                                                    <span style='vertical-align: middle;'>Disabled</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigWontApply -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-secondary'>
                                                    <span style='vertical-align: middle;'>Does not apply</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigReadonly -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>Read Only</span>
                                                    <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    $Output += $PolicyPills

                                    $Output += "</td>"

                                    $Output += "
                                        <td>$($ConfigData)</td>
                                    "
                                }

  
                                $Output += "
                                    <td style='text-align:right'>

                                    <div class='d-flex justify-content-end'>
                                "

                                if($($o.InfoText) -match "This is a Built-In/Default policy")
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"
                                    
                                }
                                elseif($($o.InfoText) -match "The policy is not enabled and will not apply")
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"                             
                                    
                                }
                                elseif($o.Level -eq [ORCAConfigLevel]::Informational)
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"
                              
                                }
                                else
                                {
                                    $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>$($LevelText)</span>
                                                    <span class='$($oicon)' style='vertical-align: middle;'></span>
                                                </div>"
                                

                                if($Check.ChiValue -ne [ORCACHI]::NotRated -and $o.Level -ne [ORCAConfigLevel]::Informational)
                                {
                                    $Output += "
                                                <div class='flex-row badge badge-pill $($chipill)'>
                                                    <span class='$($chiicon)' style='vertical-align: middle;'></span>
                                                    <span style='vertical-align: middle;'>$($chipts)</span>     
                                                </div>
                                    "
                                }            
                            }
                                $Output += "

                                    </div>

                                    </td>
                                </tr>
                                "
                            }

                            $Output +="
                                    </tbody>
                                </table>"
                                


                            $Output +="
                            </div>"

                        }

                        # If any links exist
                        If($Check.Links)
                        {
                            $Output += "
                            <table>"
                            ForEach($Link in $Check.Links.Keys) {
                                $Output += "
                                <tr>
                                <td style='width:40px'><i class='fas fa-external-link-alt'></i></td>
                                <td><a href='$($Check.Links[$Link])'>$Link</a></td>
                                <tr>
                                "
                            }
                            $Output += "
                            </table>
                            "
                        }

                        $Output += "
                            </div>
                        </div>  "
        }            

        # End the card
        $Output+=   "
            </div>
        </div>"

    }
    <#

        OUTPUT GENERATION / Footer

    #>

    $Output += "
            </main>
            </div>

            <footer class='app-footer'>
            <p><center>Bugs? Issues? Suggestions? <a href='https://aka.ms/orca-github'>GitHub!</a><center></p>
            </footer>
        </body>"

    <#
    
        CHART GENERATION
    
    #>

    $Output += "<script>

    const ctx = document.getElementById('chartOverview');"

    $Output += $this.getChartDataOverview($HistoricData)

    $Output += "let chart = new Chart(ctx, {
        type: 'line',
        data: data,
        
        options: {
          scales: {
            x: {
              type: 'time',
              time: {
                unit: 'day'
                }
            }
          },
        },
      });
  </script>"

    $Output += "</html>"


        # Write to file

        $OutputDir = $this.GetOutputDir();

        $ReportFileName = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').html"

        $OutputFile = "$OutputDir\$ReportFileName"

        $Output | Out-File -FilePath $OutputFile

        If($this.DisplayReport)
        {
            
            Invoke-Expression "&'$OutputFile'"
        }

        $this.Completed = $True
        $this.Result = $OutputFile

    }

    [string]GetOutputDir()
    {
        if($null -eq $this.OutputDirectory)
        {
            return $this.DefaultOutputDirectory
        }
        else 
        {
            return $this.OutputDirectory
        }
    }

    [string]getChartDataOverview($HistoricData)
    {

        $Output = "";
        $Output += "const data = {"
        $Output += "labels: ["
        # Build labels
        foreach($dataSet in $HistoricData)
        {
            $Output += "new Date('$($dataSet.ReportDate)'),"
        }

        # build dataset Recommendation OK InfoCount
        $Output += "],
        datasets: [{
            label: 'Info',
            borderColor: '#adb5bd',
            backgroundColor: '#adb5bd',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.InfoCount),"
            }

            $Output += "],
          },
          {
            label: 'Recommendation',
            borderColor: '#ffc107',
            backgroundColor: '#ffc107',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.Recommendation),"
            }

            $Output += "],
          },
          {
            label: 'OK',
            borderColor: '#198754',
            backgroundColor: '#198754',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.OK),"
            }

            $Output += "],
          }],
        };"
        return $Output += "`n"
    }

    [Object[]]GetHistoricData($Current,$Tenant)
    {
        $HistoricData = @($Current)


        # Get reports in outputdirectory
        try {

            $Path = $($this.GetOutputDir() + "\ORCA-$($Tenant)-*.html");
    
            $MatchingReports = Get-ChildItem $Path
            ForEach($MatchReport in $MatchingReports)
            {
                # Get the first line
                $FirstLines = Get-Content $MatchReport -First 2
                if($FirstLines[0] -like "<!-- checkjson*")
                {
                    # Get the underlying object
                    $DecodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($FirstLines[1]))
                    $Object = ConvertFrom-Json $DecodedText

                    if($Object.Tenant -eq $Tenant)
                    {
                        Write-Host "$(Get-Date) Output - HTML - Got historic data for tenant $($Tenant) in $($MatchReport.FullName)"
                        $HistoricData += $Object
                    }
                }
            }
        }
        catch {
            <#Do this if a terminating exception happens#>
        }

        return $HistoricData;
    }

}