using module "..\ORCA.psm1"

class ORCA108 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA108()
    {
        $this.Control="108"
        $this.Area="DKIM"
        $this.Name="Signing Configuration"
        $this.PassText="DKIM signing is set up for all your custom domains"
        $this.FailRecommendation="Set up DKIM signing to sign your emails"
        $this.Importance="DKIM signing can help protect the authenticity of your messages in transit and can assist with deliverability of your email messages."
        $this.ExpandResults=$True
        $this.ItemName="Domain"
        $this.DataType="Signing Setting"
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
                    if($DkimSigningConfig.Enabled -eq $false)
                    {
                        $this.Results += New-Object -TypeName psobject -Property @{
                            Result="Fail"
                            Check=$Check
                            ConfigItem=$($DkimSigningConfig.Domain)
                            Rule="DKIM Signing Disabled"
                            Control=$this.Control
                        }    
                    } 
                    else
                    {
                        $this.Results += New-Object -TypeName psobject -Property @{
                            Result="Pass"
                            Check=$Check
                            ConfigItem=$($DkimSigningConfig.Domain)
                            Rule="DKIM Signing Enabled"
                            Control=$this.Control
                        }         
                    }
                }
                Else
                {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Check=$Check
                        ConfigItem=$($AcceptedDomain.Name)
                        Rule="No DKIM Signing Config"
                        Control=$this.Control
                    } 
                }
    
            }
    
        }           

    }

}