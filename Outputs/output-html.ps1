using module "..\ORCA.psm1"

class html : ORCAOutput
{

    $OutputDirectory=$null
    $DisplayReport=$True

    html()
    {
        $this.Name="HTML"
    }

    RunOutput($Checks,$Collection)
    {
    <#

        OUTPUT GENERATION / Header

    #>

    # Obtain the tenant domain and date for the report
    $TenantDomain = ($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName
    $ReportDate = $(Get-Date -format 'dd-MMM-yyyy HH:mm')

    # Summary
    $RecommendationCount = $($Checks | Where-Object {$_.Result -eq "Fail"}).Count
    $OKCount = $($Checks | Where-Object {$_.Result -eq "Pass"}).Count
    $InfoCount = $($Checks | Where-Object {$_.Result -eq "Informational"}).Count

    # Misc
    $ReportTitle = "Office 365 ATP Recommended Configuration Analyzer Report"

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

                            <strong>Version $($this.VersionCheck.Version.ToString())</strong>
                            
                            <p>This report details any tenant configuration changes recommended within your tenant.</p>"

        <#

                OUTPUT GENERATION / Version Warning

        #>
        
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

                <div class='row p-3'>"

                if($InfoCount -gt 0)
                {
                    $Output += "
                    
                            <div class='col d-flex justify-content-center text-center'>
                                <div class='card text-white bg-secondary mb-3' style='width: 18rem;'>
                                    <div class='card-header'><h5>Informational</h4></div>
                                    <div class='card-body'>
                                    <h2>$($InfoCount)</h5>
                                    </div>
                                </div>
                            </div>
                    
                    "
                }

$Output +=        "<div class='col d-flex justify-content-center text-center'>
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
            </div>"

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
        $Fail = @($Area.Group | Where-Object {$_.Result -eq "Fail"}).Count
        $Info = @($Area.Group | Where-Object {$_.Result -eq "Informational"}).Count

        $Icon = $AreaIcon[$Area.Name]
        If($Null -eq $Icon) { $Icon = $AreaIcon["Default"]}

        $Output += "
        <tr>
            <td width='20'><i class='$Icon'></i>
            <td><a href='`#$($Area.Name)'>$($Area.Name)</a></td>
            <td align='right'>
                <span class='badge badge-secondary' style='padding:15px;text-align:center;width:40px;"; if($Info -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Info)</span>
                <span class='badge badge-warning' style='padding:15px;text-align:center;width:40px;"; if($Fail -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Fail)</span>
                <span class='badge badge-success' style='padding:15px;text-align:center;width:40px;"; if($Pass -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Pass)</span>
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
        ForEach ($Check in ($Area.Group | Sort-Object Result -Descending)) 
        {

            $Output += "        
                <h5>$($Check.Name)</h5>"

                    If($Check.Result -eq "Pass") 
                    {
                        $CalloutType = "bd-callout-success"
                        $BadgeType = "badge-success"
                        $BadgeName = "OK"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.PassText
                    } 
                    ElseIf($Check.Result -eq "Informational") 
                    {
                        $CalloutType = "bd-callout-secondary"
                        $BadgeType = "badge-secondary"
                        $BadgeName = "Informational"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.FailRecommendation
                    }
                    Else 
                    {
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
                                if($o.Level -ne [ORCAConfigLevel]::None -and $o.Level -ne [ORCAConfigLevel]::Informational) 
                                {
                                    $oicon="fas fa-check-circle text-success"
                                    $LevelText = $o.Level.ToString()
                                }
                                ElseIf($o.Level -eq [ORCAConfigLevel]::Informational) 
                                {
                                    $oicon="fas fa-info-circle text-muted"
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

                                If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                                {
                                    # Object, property, value checks need three columns
                                    $Output += "
                                        <td>$($o.Object)</td>
                                        <td>$($ConfigItem)</td>
                                        <td>$($ConfigData)</td>
                                    "
                                }
                                Else 
                                {
                                    $Output += "
                                        <td>$($ConfigItem)</td>
                                        <td>$($ConfigData)</td>
                                    "
                                }

                                $Output += "
                                    <td style='text-align:right'>
                                        <div class='row badge badge-pill badge-light'>
                                            <span style='vertical-align: middle;'>$($LevelText)</span>
                                            <span class='$($oicon)' style='vertical-align: middle;'></span>
                                        </div>
                                    </td>
                                </tr>
                                "

                                # Informational segment
                                if($o.Level -eq [ORCAConfigLevel]::Informational)
                                {
                                    $Output += "
                                    <tr>"
                                    If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                                    {
                                        $Output += "<td colspan='4' style='border: 0;'>"
                                    }
                                    else
                                    {
                                        $Output += "<td colspan='3' style='border: 0;'>"
                                    }

                                    $Output += "
                                    <div class='alert alert-light' role='alert' style='text-align: right;'>
                                    <span class='fas fa-info-circle text-muted' style='vertical-align: middle; padding-right:5px'></span>
                                    <span style='vertical-align: middle;'>$($o.InfoText)</span>
                                    </div>
                                    "
                                    
                                    $Output += "</td></tr>
                                    
                                    "
                                }

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


        # Write to file

        if($null -eq $this.OutputDirectory)
        {
            $OutputDir = $this.DefaultOutputDirectory
        }
        else 
        {
            $OutputDir = $this.OutputDirectory
        }

        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
        $ReportFileName = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').html"

        $OutputFile = "$OutputDir\$ReportFileName"

        $Output | Out-File -FilePath $OutputFile

        If($this.DisplayReport)
        {
            Invoke-Expression $OutputFile
        }

        $this.Completed = $True
        $this.Result = $OutputFile

    }

}