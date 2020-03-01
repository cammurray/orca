using module "..\ORCA.psm1"

class ORCA113 : ORCACheck
{
    <#
    
        Check if AllowClickThrough is disabled in the organisation wide SafeLinks policy and if AllowClickThrough is False and DoNotAllowClickThrough is True in SafeLink policies
    
    #>

    ORCA113()
    {
        $this.Control="ORCA-113"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Do not let users click through safe links"
        $this.PassText="AllowClickThrough is disbaled in Safe Links policies"
        $this.FailRecommendation="Do not let users click through safe links to original URL"
        $this.Importance="Office 365 ATP Safe Links can help protect your organization by providing time-of-click verification of  web addresses (URLs) in email messages and Office documents. It is possible to allow users click through Safe Links to the original URL. It is recommended to configure Safe Links policies to not let users click through safe links."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Office 365 ATP Safe Links policies"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-atp-safe-links-policies?view=o365-worldwide#step-4-learn-about-atp-safe-links-policy-options"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp?view=o365-worldwide#office-365-advanced-threat-protection-security"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        If($Config["AtpPolicy"].AllowClickThrough -eq $True)
        {
            # Determine if AllowClickThrough is enabled in the policy applies to the entire organization
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Fail"
                Object=$($Config["AtpPolicy"].Name)
                ConfigItem="AllowClickThrough"
                ConfigData=$($Config["AtpPolicy"].AllowClickThrough)
                Control=$this.Control
            }
        }
        Else
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Pass"
                Object=$($Config["AtpPolicy"].Name)
                ConfigItem="AllowClickThrough"
                ConfigData=$($Config["AtpPolicy"].AllowClickThrough)
                Control=$this.Control
            }            
        }
        
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
            # Determine if AllowClickThrough is False and DoNotAllowClickThrough is True in safelinks policies
            If($Policy.AllowClickThrough -eq $false -and $Policy.DoNotAllowClickThrough -eq $true)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="AllowClickThrough"
                    ConfigData=$($Policy.AllowClickThrough)
                    Control=$this.Control
                }
            } 
            else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="AllowClickThrough"
                    ConfigData=$($Policy.AllowClickThrough)
                    Control=$this.Control
                }
            }
        }

    }

}