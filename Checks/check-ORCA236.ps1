<#

ORCA-236

Checks to determine if SafeLinks action for unknown potentially malicious URLs in emails

#>

using module "..\ORCA.psm1"

class ORCA236 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA236()
    {
        $this.Control=236
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Links protections for links in email"
        $this.PassText="Safe Links is enabled for emails"
        $this.FailRecommendation="Enable Safe Links policy action for unknown potentially malicious URLs in emails"
        $this.Importance="When Safe Links for emails is enabled, URLs in emails will be checked when users click on links."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Safe Links policy"
        $this.ChiValue=[ORCACHI]::Medium
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://aka.ms/orca-atpp-action-safelinksv2"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {

            # Policy is turned on, default false
            $PolicyEnabled = $false

            $PolicyName = $($Policy.Name)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$PolicyName
            $ConfigObject.ConfigItem="EnableSafeLinksForEmail"
            $ConfigObject.ConfigData=$Policy.EnableSafeLinksForEmail

            if($Policy.EnableSafeLinksForEmail -eq $true)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            $this.AddConfig($ConfigObject)
        }

    }

}