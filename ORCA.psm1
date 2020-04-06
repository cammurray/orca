#Requires -Version 5.1

<#
	.SYNOPSIS
		The Office 365 Recommended Configuration Analyzer (ORCA)

	.DESCRIPTION
       

	.NOTES
		Cam Murray
		Senior Program Manager - Microsoft
        camurray@microsoft.com
        
        Daniel Mozes
        Senior Program Manager - Microsoft
        damozes@microsoft.com

        Output report uses open source components for HTML formatting
        - bootstrap - MIT License - https://getbootstrap.com/docs/4.0/about/license/
        - fontawesome - CC BY 4.0 License - https://fontawesome.com/license/free
        
        ############################################################################

        This sample script is not supported under any Microsoft standard support program or service. 
        This sample script is provided AS IS without warranty of any kind. 
        Microsoft further disclaims all implied warranties including, without limitation, any implied 
        warranties of merchantability or of fitness for a particular purpose. The entire risk arising 
        out of the use or performance of the sample script and documentation remains with you. In no
        event shall Microsoft, its authors, or anyone else involved in the creation, production, or 
        delivery of the scripts be liable for any damages whatsoever (including, without limitation, 
        damages for loss of business profits, business interruption, loss of business information, 
        or other pecuniary loss) arising out of the use of or inability to use the sample script or
        documentation, even if Microsoft has been advised of the possibility of such damages.

        ############################################################################    

	.LINK
        about_functions_advanced

#>

function Get-ORCADirectory
{
    <#

        Gets or creates the ORCA directory in AppData
        
    #>

    $Directory = "$($env:LOCALAPPDATA)\Microsoft\ORCA"

    If(Test-Path $Directory) 
    {
        Return $Directory
    }
    else 
    {
        mkdir $Directory | out-null
        Return $Directory
    }

}

Function Invoke-ORCAConnections
{
    <#
    
    Check which module is loaded and then run the respective connection
    
    #>

    If(Get-Command "Connect-EXOPSSession" -ErrorAction:SilentlyContinue)
    {
        Write-Host "$(Get-Date) Connecting to Exchange Online.."
        Connect-EXOPSSession -PSSessionOption $ProxySetting -WarningAction:SilentlyContinue | Out-Null    
    } 
    ElseIf(Get-Command "Connect-ExchangeOnline" -ErrorAction:SilentlyContinue)
    {
        Write-Host "$(Get-Date) Connecting to Exchange Online (Modern Module).."
        Connect-ExchangeOnline -WarningAction:SilentlyContinue | Out-Null
    }
    Else 
    {
        Throw "ORCA requires either the Exchange Online PowerShell Module (aka.ms/exopsmodule) loaded or the Exchange Online PowerShell module from the PowerShell Gallery installed."
    }

    # Perform check for Exchange Connection Status
    If($(Get-EXConnectionStatus) -eq $False)
    {
        Throw "ORCA was unable to connect to Exchange Online."
    }
}

enum CheckType
{
    ObjectPropertyValue
    PropertyValue
}

[Flags()]
enum ORCAService
{
    EOP = 1
    OATP = 2
}

enum ORCAConfigLevel
{
    None = 0
    Standard = 5
    Strict = 10
}

Class ORCACheckConfig
{

    ORCACheckConfig()
    {
        # Constructor

        $this.Results += New-Object -TypeName ORCACheckConfigResult -Property @{
            Level=[ORCAConfigLevel]::Standard
        }

        $this.Results += New-Object -TypeName ORCACheckConfigResult -Property @{
            Level=[ORCAConfigLevel]::Strict
        }

    }

    # Set the result for this mode
    SetResult([ORCAConfigLevel]$Level,$Result)
    {
        ($this.Results | Where-Object {$_.Level -eq $Level}).Value = $Result

        # The level of this configuration should be its strongest result (e.g if its currently standard and we have a strict pass, we should make the level strict)
        if($Result -eq "Pass" -and ($this.Level -lt $Level -or $this.Level -eq [ORCAConfigLevel]::None))
        {
            $this.Level = $Level
        }

    }

    $Check
    $Object
    $ConfigItem
    $ConfigData
    [array]$Results
    [ORCAConfigLevel]$Level
}

Class ORCACheckConfigResult
{
    [ORCAConfigLevel]$Level=[ORCAConfigLevel]::Standard
    $Value
}

Class ORCACheck
{
    <#

        Check definition

        The checks defined below allow contextual information to be added in to the report HTML document.
        - Control               : A unique identifier that can be used to index the results back to the check
        - Area                  : The area that this check should appear within the report
        - PassText              : The text that should appear in the report when this 'control' passes
        - FailRecommendation    : The text that appears as a title when the 'control' fails. Short, descriptive. E.g "Do this"
        - Importance            : Why this is important
        - ExpandResults         : If we should create a table in the callout which points out which items fail and where
        - ObjectType            : When ExpandResults is set to, For Object, Property Value checks - what is the name of the Object, e.g a Spam Policy
        - ItemName              : When ExpandResults is set to, what does the check return as ConfigItem, for instance, is it a Transport Rule?
        - DataType              : When ExpandResults is set to, what type of data is returned in ConfigData, for instance, is it a Domain?    

    #>

    [Array] $Config=@()
    [string] $Control
    [String] $Area
    [String] $Name
    [String] $PassText
    [String] $FailRecommendation
    [Boolean] $ExpandResults=$false
    [String] $ObjectType
    [String] $ItemName
    [String] $DataType
    [String] $Importance
    [ORCAService]$Services = [ORCAService]::EOP
    [CheckType] $CheckType = [CheckType]::PropertyValue
    $Links

    [String] $Result="Pass"
    [int] $FailCount=0
    [int] $PassCount=0
    [Boolean] $Completed=$false
    
    # Overridden by check
    GetResults($Config) { }

    AddConfig([ORCACheckConfig]$Config)
    {
        $this.Config += $Config

        $this.FailCount = @($this.Config | Where-Object {$_.Level -eq [ORCAConfigLevel]::None}).Count
        $this.PassCount = @($this.Config | Where-Object {$_.Level -ne [ORCAConfigLevel]::None}).Count

        If($this.FailCount -eq 0)
        {
            $this.Result = "Pass"
        }
        else 
        {
            $this.Result = "Fail"
        }
    }

    # Run
    Run($Config)
    {
        Write-Host "$(Get-Date) Analysis - $($this.Area) - $($this.Name)"
        
        $this.GetResults($Config)

        # If there is no results to expand, turn off ExpandResults
        if($this.Config.Count -eq 0)
        {
            $this.ExpandResults = $false
        }

        # Set check module to completed
        $this.Completed=$true
    }

}

Function Get-ORCACheckDefs
{

    $Checks = @()

    # Load individual check definitions
    $CheckFiles = Get-ChildItem "$PSScriptRoot\Checks"

    ForEach($CheckFile in $CheckFiles)
    {
        if($CheckFile.BaseName -match '^check-(.*)$')
        {
            Write-Verbose "Importing $($matches[1])"
            . $CheckFile.FullName
            $Checks += New-Object -TypeName $matches[1]
        }
    }

    Return $Checks
}

Function Get-ORCACollection
{
    $Collection = @{}

    [ORCAService]$Collection["Services"] = [ORCAService]::EOP

    # Determine if ATP is available by checking for presence of an ATP command
    if($(Get-command Get-AtpPolicyForO365 -ErrorAction:SilentlyContinue))
    {
        $Collection["Services"] += [ORCAService]::OATP
    } 

    If(!$Collection["Services"] -band [ORCAService]::OATP)
    {
        Write-Host "$(Get-Date) Office ATP is not detected - these checks will be skipped!" -ForegroundColor Red
    }

    Write-Host "$(Get-Date) Getting Anti-Spam Settings"
    $Collection["HostedConnectionFilterPolicy"] = Get-HostedConnectionFilterPolicy
    $Collection["HostedContentFilterPolicy"] = Get-HostedContentFilterPolicy
    $Collection["HostedContentFilterRule"] = Get-HostedContentFilterRule
    $Collection["HostedOutboundSpamFilterPolicy"] = Get-HostedOutboundSpamFilterPolicy

    Write-Host "$(Get-Date) Getting Tenant Settings"
    $Collection["AdminAuditLogConfig"] = Get-AdminAuditLogConfig

    If($Collection["Services"] -band [ORCAService]::OATP)
    {
        Write-Host "$(Get-Date) Getting Anti Phish Settings"
        $Collection["AntiPhishPolicy"] = Get-AntiphishPolicy
    }

    Write-Host "$(Get-Date) Getting Anti-Malware Settings"
    $Collection["MalwareFilterPolicy"] = Get-MalwareFilterPolicy
    $Collection["MalwareFilterRule"] = Get-MalwareFilterRule

    Write-Host "$(Get-Date) Getting Transport Rules"
    $Collection["TransportRules"] = Get-TransportRule

    If($Collection["Services"] -band [ORCAService]::OATP)
    {
        Write-Host "$(Get-Date) Getting ATP Policies"
        $Collection["SafeAttachmentsPolicy"] = Get-SafeAttachmentPolicy
        $Collection["SafeAttachmentsRules"] = Get-SafeAttachmentRule
        $Collection["SafeLinksPolicy"] = Get-SafeLinksPolicy
        $Collection["SafeLinksRules"] = Get-SafeLinksRule
        $Collection["AtpPolicy"] = Get-AtpPolicyForO365
    }

    Write-Host "$(Get-Date) Getting Accepted Domains"
    $Collection["AcceptedDomains"] = Get-AcceptedDomain

    Write-Host "$(Get-Date) Getting DKIM Configuration"
    $Collection["DkimSigningConfig"] = Get-DkimSigningConfig

    Return $Collection
}

Function Get-ORCAHtmlOutput
{
    <#

        OUTPUT GENERATION / Header

    #>
    Param(
        $Collection,
        $Checks,
        $VersionCheck
    )

    Write-Host "$(Get-Date) Generating Output" -ForegroundColor Green

    # Obtain the tenant domain and date for the report
    $TenantDomain = ($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName
    $ReportDate = $(Get-Date -format 'dd-MMM-yyyy HH:mm')

    # Summary
    $RecommendationCount = $($Checks | Where-Object {$_.Result -eq "Fail"}).Count
    $OKCount = $($Checks | Where-Object {$_.Result -eq "Pass"}).Count

    # Misc
    $ReportTitle = "Office 365 ATP Recommended Configuration Analyzer Report"

    # Area icons
    $AreaIcon = @{}
    $AreaIcon["Default"] = "fas fa-user-cog"
    $AreaIcon["Content Filter Policies"] = "fas fa-scroll"
    $AreaIcon["Malware Filter Policy"] = "fas fa-biohazard"
    $AreaIcon["Zero Hour Autopurge"] = "fas fa-trash"
    $AreaIcon["DKIM"] = "fas fa-file-signature"
    $AreaIcon["Transport Rules"] = "fas fa-list"
    $AreaIcon["Transport Rules"] = "fas fa-list"

    # Output start
    $output = "<!doctype html>
    <html lang='en'>
    <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/css/all.min.css' crossorigin='anonymous'>
        <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>


        <script src='https://code.jquery.com/jquery-3.3.1.slim.min.js' integrity='sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo' crossorigin='anonymous'></script>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js' integrity='sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1' crossorigin='anonymous'></script>
        <script src='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js' integrity='sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM' crossorigin='anonymous'></script>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/js/all.js'></script>

        <style>
        .table-borderless td,
        .table-borderless th {
            border: 0;
        }
        .bd-callout {
            padding: 1.25rem;
            margin-top: 1.25rem;
            margin-bottom: 1.25rem;
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

        </style>

        <title>$($ReportTitle)</title>

    </head>
    <body class='app header-fixed bg-light'>

        <nav class='navbar fixed-top navbar-light bg-white p-3 border-bottom'>
            <div class='container-fluid'>
                <div class='col-sm' style='text-align:left'>
                    <div class='row'><div><i class='fas fa-binoculars'></i></div><div class='ml-3'><strong>ORCA</strong></div></div>
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
                            <h2 class='card-title'>$($ReportTitle)</h5>
                            <strong>Version $($VersionCheck.Version.ToString())</strong>
                            <p>This report details any tenant configuration changes recommended within your tenant.</p>"

        <#

                OUTPUT GENERATION / Version Warning

        #>
                                
        If($VersionCheck.Updated -eq $False) {

            $Output += "
            <div class='alert alert-danger pt-2' role='alert'>
                ORCA is out of date. You're running version $($VersionCheck.Version) but version $($VersionCheck.GalleryVersion) is available! Run Update-Module ORCA to get the latest definitions!
            </div>
            
            "
        }

        If(!($Collection["Services"] -band [ORCAService]::OATP))
        {
            $Output += "
            <div class='alert alert-danger pt-2' role='alert'>
                <p>Office Advanced Threat Protection (ATP) was <strong>NOT</strong> detected on this tenant. <strong>The purpose of ORCA is to check for Office ATP recommended configuration</strong> - <i>however, these checks will be skipped. Other results should be relevant to base EOP configuration.</i></p>
                <p>Consider Office Advanced Threat Protection for:<ul><li>Automatic incident response capabilities</li><li>Attack simulation capabilities</li><li>Behavioural analysis (sandboxing) of malware</li><li>Time of click protection against URLs</li><li>Advanced anti-phishing controls</li></ul></p>
            </div>
            
            "    
        }


                        $Output += "</div>
                </div>"



    <#

        OUTPUT GENERATION / Summary cards

    #>

    $Output += "

                <div class='row p-3'>

                <div class='col d-flex justify-content-center text-center'>
                    <div class='card text-white bg-warning mb-3' style='width: 18rem;'>
                        <div class='card-header'><h5>Recommendations</h4></div>
                        <div class='card-body'>
                        <h2>$($RecommendationCount)</h3>
                        </div>
                    </div>
                </div>

                <div class='col d-flex justify-content-center text-center'>
                    <div class='card text-white bg-success mb-3' style='width: 18rem;'>
                        <div class='card-header'><h5>OK</h4></div>
                        <div class='card-body'>
                        <h2>$($OKCount)</h5>
                        </div>
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

        $Pass = @($Area.Group | Where-Object {$_.Result -eq "Pass"}).Count
        $Fail = @($Area.Group | Where-Object {$_.Result -ne "Pass"}).Count
        $Icon = $AreaIcon[$Area.Name]
        If($Null -eq $Icon) { $Icon = $AreaIcon["Default"]}

        $Output += "
        <tr>
            <td width='20'><i class='$Icon'></i>
            <td><a href='`#$($Area.Name)'>$($Area.Name)</a></td>
            <td align='right'>
                <span class='badge badge-warning' style='padding:15px'>$($Fail)</span>
                <span class='badge badge-success' style='padding:15px'>$($Pass)</span>
            </td>
        </tr>
        "
    }

    $Output+="</table>
        </div>
    </div>
    "

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
        ForEach ($Check in $Area.Group) {

            $Output += "        
                <h5>$($Check.Name)</h5>"

                    If($Check.Result -eq "Pass") {
                        $CalloutType = "bd-callout-success"
                        $BadgeType = "badge-success"
                        $BadgeName = "OK"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.PassText
                    } Else {
                        $CalloutType = "bd-callout-warning"
                        $BadgeType = "badge-warning"
                        $BadgeName = "Improvement"
                        $Icon = "fas fa-thumbs-down"
                        $Title = $Check.FailRecommendation
                    }

                    $Output += "  
                    
                        <div class='bd-callout $($CalloutType) b-t-1 b-r-1 b-b-1 p-3'>
                            <div class='container-fluid'>
                                <div class='row'>
                                    <div class='col-1'><i class='$($Icon)'></i></div>
                                    <div class='col-8'><h5>$($Title)</h5></div>
                                    <div class='col' style='text-align:right'><h5><span class='badge $($BadgeType)'>$($BadgeName)</span></h5></div>
                                </div>"

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
                                            <th style='width:50px'></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                            "

                            ForEach($o in $Check.Config)
                            {
                                if($o.Level -ne [ORCAConfigLevel]::None) 
                                {
                                    $oicon="fas fa-check-circle text-success"
                                    $LevelText = $o.Level.ToString()
                                } 
                                Else
                                {
                                    $oicon="fas fa-times-circle text-danger"
                                    $LevelText = "Not Recommended"
                                }

                                $Output += "
                                <tr>
                                "

                                If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                                {
                                    # Object, property, value checks need three columns
                                    $Output += "
                                        <td>$($o.Object)</td>
                                        <td>$($o.ConfigItem)</td>
                                        <td>$($o.ConfigData)</td>
                                    "
                                }
                                Else 
                                {
                                    $Output += "
                                        <td>$($o.ConfigItem)</td>
                                        <td>$($o.ConfigData)</td>
                                    "
                                }

                                $Output += "
                                    <td>
                                        <div class='row badge badge-pill badge-light'>
                                            <span style='vertical-align: middle;'>$($LevelText)</span>
                                            <span class='$($oicon)' style='vertical-align: middle;'></span>
                                        </div>
                                    </td>
                                </tr>
                                "
                            }

                            $Output +="
                                    </tbody>
                                </table>"
                                
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

                            $Output +="
                            </div>"

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
            <p><center>Bugs? Issues? Suggestions? <a href='https://github.com/cammurray/orca'>GitHub!</a><center></p>
            </footer>
        </body>
    </html>"

    Return $Output
}

function Invoke-ORCAVersionCheck
{
    Param(
        $Terminate
    )

    Write-Host "$(Get-Date) Performing ORCA Version check..."

    $ORCAVersion = (Get-Module ORCA | Sort-Object Version -Desc)[0].Version
    $PSGalleryVersion = (Find-Module ORCA -Repository PSGallery -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue).Version

    If($PSGalleryVersion -gt $ORCAVersion)
    {
        $Updated = $False
        If($Terminate)
        {
            Throw "ORCA is out of date. Your version is $ORCAVersion and the published version is $PSGalleryVersion. Run Update-Module ORCA or run Get-ORCAReport with -NoUpdate."
        }
        else {
            Write-Host "$(Get-Date) ORCA is out of date. Your version: $($ORCAVersion) published version is $($PSGalleryVersion)"
        }
    }
    else
    {
        $Updated = $True
    }

    Return New-Object -TypeName PSObject -Property @{
        Updated=$Updated
        Version=$ORCAVersion
        GalleryVersion=$PSGalleryVersion
    }
}

function Get-EXConnectionStatus
{
    # Perform check to determine if we are connected
    Try
    {
        Get-Mailbox -ResultSize:1 -WarningAction:SilentlyContinue | Out-Null
        Return $True
    }
    Catch
    {
        Return $False
    }
}

Function Get-ORCAReport
{
    <#
    	.SYNOPSIS
		The Office 365 Recommended Configuration Analyzer (ORCA) Report Generator

        .DESCRIPTION
        Office 365 Recommended Configuration Analyzer (ORCA)

        The Get-ORCAReport command generates a HTML report based on recommended practices based
        on field experiences working with Exchange Online Protection and Advanced Threat Protection.

        Output report uses open source components for HTML formatting
        - bootstrap - MIT License - https://getbootstrap.com/docs/4.0/about/license/
        - fontawesome - CC BY 4.0 License - https://fontawesome.com/license/free

        Engine and report generation
        Cam Murray
		Field Engineer - Microsoft
        camurray@microsoft.com

        With assistance from
        Daniel Mozes
        Field Engineer - Microsoft
        damozes@microsoft.com
        
        https://github.com/cammurray/orca

        .PARAMETER Report

        Optional.

        Full path to the report file that you want to generate. If this is not specified,
        a directory in your current users AppData is created called ORCA. Reports are generated in this
        directory in the following format:

        ORCA-tenantname-date.html

        .PARAMETER NoUpdate

        Optional.

        Switch that will tell the script not to exit in the event you are running an outdated rule
        definition. It's always recommended to be running the latest rule definition/module.

        .PARAMETER NoConnect

        Optional.

        Switch that will instruct ORCA not to connect and to use an already established connection
        to Exchange Online.
        
        .PARAMETER Collection

        Optional.

        For passing an already established collection object. Can be used for offline collection
        analysis.

        .EXAMPLE

        Get-ORCAReport

        .EXAMPLE

        Get-ORCAReport -Report myreport.html

        .EXAMPLE

        Get-ORCAReport -Report myreport.html -NoConnect
        
    #>
    Param(
        [CmdletBinding()]
        [Switch]$NoConnect,
        [Switch]$NoUpdate,
        [Switch]$NoVersionCheck,
        $Collection,
        $Output
    )

    # Version check
    If(!$NoVersionCheck)
    {
        $VersionCheck = Invoke-ORCAVersionCheck
    }
    
    # Unless -NoConnect specified (already connected), connect to Exchange Online
    If(!$NoConnect -and (Get-EXConnectionStatus) -eq $False) {
        Invoke-ORCAConnections
    }

    # Get the object of ORCA checks
    $Checks = Get-ORCACheckDefs

    # Get the collection in to memory. For testing purposes, we support passing the collection as an object
    If($Null -eq $Collection)
    {
        $Collection = Get-ORCACollection
    }

    # Perform checks inside classes/modules
    ForEach($Check in ($Checks | Sort-Object Area))
    {

        # Run EOP checks by default
        if($check.Services -band [ORCAService]::EOP)
        {
            $Check.Run($Collection)
        }

        # Run ATP checks only when ATP is present
        if($check.Services -band [ORCAService]::OATP -and $Collection["Services"] -band [ORCAService]::OATP)
        {
            $Check.Run($Collection)
        }
    }

    # Generate HTML Output
    $HTMLReport = Get-ORCAHtmlOutput -Collection $Collection -Checks $Checks -VersionCheck $VersionCheck -Mode $Mode

    # Write to file

    If(!$Output)
    {
        $OutputDirectory = Get-ORCADirectory
        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
        $ReportFileName = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').html"
        $Output = "$OutputDirectory\$ReportFileName"
    }

    $HTMLReport | Out-File -FilePath $Output
    Write-Host "$(Get-Date) Complete! Output is in $Output"
    Invoke-Expression $Output

}
