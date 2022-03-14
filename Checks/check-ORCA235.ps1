using module "..\ORCA.psm1"

class ORCA235 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA235()
    {
        $this.Control="235"
        $this.Area="SPF"
        $this.Name="SPF Records"
        $this.PassText="SPF records is set up for all your custom domains"
        $this.FailRecommendation="Set up SPF records to prevent spoofing"
        $this.Importance="SPF helps validate outbound email sent from your custom domain. Microsoft 365 uses the Sender Policy Framework (SPF) TXT record in DNS to ensure that destination email systems trust messages sent from your custom domain."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Domain"
        $this.ItemName="SPF Record Lookup"
        $this.DataType="Is HardFail"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            "Use SPF to validate outbound email sent from your custom domain in Office 365"="https://aka.ms/orca-spf-docs-1"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        # Check DKIM is enabled
        ForEach($AcceptedDomain in $Config["AcceptedDomains"]) 
        {  
            $SplatParameters = @{
                'ErrorAction' = 'SilentlyContinue'
            }
            $HasMailbox = $false
            $mailbox = Resolve-DnsName -Name $($AcceptedDomain.Name)-Type MX

            try
            {
                if($null -ne $mailbox -and $mailbox.Count -gt 0)
                {
                    $HasMailbox = $true
                }
            }
            Catch{}
            
            If($HasMailbox) 
            {   
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object = $($AcceptedDomain.Name)

                $SPF = Resolve-DnsName -Name $($AcceptedDomain.Name) -Type TXT @SplatParameters | where-object { $_.strings -match "v=spf1" } | Select-Object -ExpandProperty strings -ErrorAction SilentlyContinue
                if ($SPF -match "redirect") {
                    $redirect = $SPF.Split(" ")
                    $RedirectName = $redirect -match "redirect" -replace "redirect="
                    $SPF = Resolve-DnsName -Name "$RedirectName" -Type TXT @SplatParameters | where-object { $_.strings -match "v=spf1" } | Select-Object -ExpandProperty strings -ErrorAction SilentlyContinue
                }

                $SpfAdvisory = "No SPF record"
                if ( $null -eq $SPF) {
                    $SpfAdvisory = "No SPF record"
                }
                if ($SPF -is [array]) {
                    $SpfAdvisory = "More than one SPF-record"
                }
                Else {
                    switch -Regex ($SPF) {
                    '~all' {
                        $SpfAdvisory = "Soft Fail"
                    }
                    '-all' {
                        $SpfAdvisory = "Hard Fail"
                    }
                    Default {
                        $SpfAdvisory = "No qualifier found"
                    }
                }
                }

                # Get matching DKIM signing configuration          
    
                If($true)
                {
                    $ConfigObject.ConfigItem="$($SPF)"

                    if($SpfAdvisory -eq "Hard Fail")
                    {
                        $ConfigObject.ConfigData = "Yes"
                    }
                    Elseif( ($SpfAdvisory -eq "Soft Fail") -or ($SpfAdvisory -eq "No qualifier found"))
                    {
                        $ConfigObject.ConfigData = "No"
                    }
                    Else
                    {
                        $ConfigObject.ConfigData = "Not Detected"
                    }

                    if($SpfAdvisory -eq "Hard Fail")
                    {
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                    }
                    Else 
                    {
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    }
                }
                Else
                {
                    $ConfigObject.ConfigItem = "Not Detected"
                    $ConfigObject.ConfigData = "Not Detected"
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                }

                # Add config to check
                $this.AddConfig($ConfigObject)
            }   
        }           
    }
}

