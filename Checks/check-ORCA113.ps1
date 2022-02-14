using module "..\ORCA.psm1"

class ORCA113 : ORCACheck
{
    <#
    
        Check if AllowClickThrough is disabled in the organisation wide SafeLinks policy and if DoNotAllowClickThrough is True in SafeLink policies
    
    #>

    ORCA113()
    {
        $this.Control="ORCA-113"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Do not let users click through safe links"
        $this.PassText="DoNotAllowClickThrough is enabled in Safe Links policies"
        $this.FailRecommendation="Do not let users click through safe links to original URL"
        $this.Importance="Office 365 ATP Safe Links can help protect your organization by providing time-of-click verification of  web addresses (URLs) in email messages and Office documents. It is possible to allow users click through Safe Links to the original URL. It is recommended to configure Safe Links policies to not let users click through safe links."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://aka.ms/orca-atpp-action-safelinksv2"
            "Office 365 ATP Safe Links policies"="https://aka.ms/orca-atpp-docs-11"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-8"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        # Check objects
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$($Config["AtpPolicy"].Name)
        $ConfigObject.ConfigItem="AllowClickThrough"
        $ConfigObject.ConfigData=$($Config["AtpPolicy"].AllowClickThrough)

        If($Config["AtpPolicy"].AllowClickThrough -eq $True)
        {
            # Determine if AllowClickThrough is enabled in the policy applies to the entire organization
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }
        Else
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")         
        }
 
        # Add config to check
        $this.AddConfig($ConfigObject)
        
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
    
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="DoNotAllowClickThrough"
            $ConfigObject.ConfigData=$($Policy.DoNotAllowClickThrough)

            # Determine if DoNotAllowClickThrough is True in safelinks policies
            If($Policy.DoNotAllowClickThrough -eq $true)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")                       
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }

    }

}