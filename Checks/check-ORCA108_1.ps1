using module "..\ORCA.psm1"

class ORCA108_1 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA108_1()
    {
        $this.Control="108-1"
        $this.Area="DKIM"
        $this.Name="DNS Records"
        $this.PassText="DNS Records have been set up to support DKIM"
        $this.FailRecommendation="Set up the required selector DNS records in order to support DKIM"
        $this.Importance="DKIM signing can help protect the authenticity of your messages in transit and can assist with deliverability of your email messages."
        $this.ExpandResults=$True
        $this.ItemName="Domain"
        $this.DataType="DNS Record"
        $this.Links= @{
            "Use DKIM to validate outbound email sent from your custom domain in Office 365"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $Check = "DKIM"
    
        # Check DKIM is enabled
    
        ForEach($AcceptedDomain in $Config["AcceptedDomains"]) 
        {
    
            If($AcceptedDomain.Name -notlike "*.onmicrosoft.com") 
            {
    
                # Get matching DKIM signing configuration
                $DkimSigningConfig = $Config["DkimSigningConfig"] | Where-Object {$_.Name -eq $AcceptedDomain.Name}
    
                If($DkimSigningConfig)
                {  
                    if($DkimSigningConfig.Enabled -eq $true)
                    {

                        # Check DKIM Selector Records
                        $Selector1 = $Null
                        Try { $Selector1 = Resolve-DnsName -Type CNAME -Name "selector1._domainkey.$($DkimSigningConfig.Domain)" -ErrorAction:stop } Catch {}
                        If($Selector1.Type -eq "CNAME" -and $Selector1.NameHost -eq $DkimSigningConfig.Selector1CNAME)
                        {
                            # DKIM Selector1 Correctly Configured
                            $this.Results += New-Object -TypeName psobject -Property @{
                                Result="Pass"
                                Check=$Check
                                ConfigItem=$($DkimSigningConfig.Domain)
                                ConfigData="Selector1 CNAME $($DkimSigningConfig.Selector1CNAME)"
                                Rule="DKIM Signing Selectors Configured"
                                Control=$this.Control
                            }
                        } 
                        else
                        {
                            $this.Results += New-Object -TypeName psobject -Property @{
                                Result="Fail"
                                Check=$Check
                                ConfigItem=$($DkimSigningConfig.Domain)
                                Rule="DKIM Signing Selectors Misconfigured"
                                ConfigData="Selector1 CNAME"
                                Control=$this.Control
                            }     
                        }
            
                        # Check DKIM Selector Records
                        $Selector2 = $Null
                        Try { $Selector2 = Resolve-DnsName -Type CNAME -Name "selector2._domainkey.$($DkimSigningConfig.Domain)" -ErrorAction:stop } Catch {}
                        If($Selector2.Type -eq "CNAME" -and $Selector2.NameHost -eq $DkimSigningConfig.Selector2CNAME)
                        {
                            # DKIM Selector2 Correctly Configured
                            $this.Results += New-Object -TypeName psobject -Property @{
                                Result="Pass"
                                Check=$Check
                                ConfigItem=$($DkimSigningConfig.Domain)
                                ConfigData="Selector2 CNAME $($DkimSigningConfig.Selector2CNAME)"
                                Rule="DKIM Signing Selectors Configured"
                                Control=$this.Control
                            }
                        }
                        else
                        {
                            $this.Results += New-Object -TypeName psobject -Property @{
                                Result="Fail"
                                Check=$Check
                                ConfigItem=$($DkimSigningConfig.Domain)
                                Rule="DKIM Signing Selectors Misconfigured"
                                ConfigData="Selector2 CNAME"
                                Control=$this.Control
                            }    
                        }            
                    }
                }
    
            }
    
        }     

    }

}