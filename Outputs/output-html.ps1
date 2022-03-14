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

        <nav class='navbar  fixed-top navbar-custom p-3 border-bottom'>
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
                            <h2 class='card-title'>$($ReportSub1)</h2>
                            
                            <div style='text-align:right;margin-top:-65px;margin-right:8px;color:#005494;';>
				                <b>Rate this report</b>
					        </div>

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
                <p>Microsoft Defender for Office 365 was <strong>NOT</strong> detected on this tenant. <strong>The purpose of ORCA is to check for Microsoft Defender for Office 365 recommended configuration</strong> - <i>however, these checks will be skipped. Other results should be relevant to base EOP configuration.</i></p>
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
            </div>"

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

            <div class='alert alert-success pt-2' >
            Like this report? Try similar reporting for Microsoft's Compliance solutions. Download <a href='https://aka.ms/orca-mcca-github' target='_blank'> Microsoft Compliance Config Analyzer (MCCA)</a>
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
                                
                                if($o.Level -ne [ORCAConfigLevel]::None -and $o.Level -ne [ORCAConfigLevel]::Informational) 
                                {
                                    $oicon="fas fa-check-circle text-success"
                                    
                                    $LevelText = $o.Level.ToString()

                                    if($Check.ChiValue -ne [ORCACHI]::NotRated)
                                    {
                                        $chiicon = "fas fa-plus"
                                        $chipill = "badge-success"
                                    }
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

                                    if($Check.ChiValue -ne [ORCACHI]::NotRated)
                                    {
                                        $chiicon = "fas fa-minus"
                                        $chipill = "badge-danger"
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

                                    <div class='d-flex justify-content-end'>
                                "

                                if($($o.InfoText) -match "This is a Built-In/Default policy")
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill badge-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    

                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"
                                    
                                }
                                elseif($($o.InfoText) -match "The policy is not enabled and will not apply")
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill badge-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"                             
                                    
                                }
                                elseif($o.Level -eq [ORCAConfigLevel]::Informational)
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill badge-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"
                              
                                }
                                else
                                {
                                    $Output += "
                                                <div class='flex-row badge badge-pill badge-light'>
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
            <p><center>Bugs? Issues? Suggestions? <a href='https://aka.ms/orca-github'>GitHub!</a><center></p>
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
            
            Invoke-Expression "&'$OutputFile'"
        }

        $this.Completed = $True
        $this.Result = $OutputFile

    }

}