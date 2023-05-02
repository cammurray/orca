<#

ORCA-237

Checks to determine if SafeLinks action for unknown potentially malicious URLs in teams

#>

using module "..\ORCA.psm1"

class ORCA237 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA237()
    {
        $this.Control=237
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Links protections for links in teams messages"
        $this.PassText="Safe Links is enabled for teams messages"
        $this.FailRecommendation="Enable Safe Links policy action for unknown potentially malicious URLs in teams messages"
        $this.Importance="When Safe Links for teamas messages is enabled, URLs in messages will be checked when users click on them."
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
            $ConfigObject.ConfigItem="EnableSafeLinksForTeams"
            $ConfigObject.ConfigData=$Policy.EnableSafeLinksForTeams

            if($Policy.EnableSafeLinksForTeams -eq $true)
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