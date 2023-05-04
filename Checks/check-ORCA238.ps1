<#

ORCA-238

Checks to determine if SafeLinks action for unknown potentially malicious URLs in teams

#>

using module "..\ORCA.psm1"

class ORCA238 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA238()
    {
        $this.Control=238
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Links protections for links in office documents"
        $this.PassText="Safe Links is enabled for office documents"
        $this.FailRecommendation="Enable Safe Links policy action for unknown potentially malicious URLs in office documents"
        $this.Importance="When Safe Links for office documents is enabled, URLs in documents will be checked when users click on them."
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
            $ConfigObject.ConfigItem="EnableSafeLinksForOffice"
            $ConfigObject.ConfigData=$Policy.EnableSafeLinksForOffice
            $ConfigObject.ConfigReadonly=$Policy.IsPreset

            if($Policy.EnableSafeLinksForOffice -eq $true)
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