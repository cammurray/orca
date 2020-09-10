<#

123 - Check ATP Phishing Enable Unusual Characters Safety Tips 

#>

using module "..\ORCA.psm1"

class ORCA123 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA123()
    {
        $this.Control=123
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Unusual Characters Safety Tips"
        $this.PassText="Unusual Characters Safety Tips is enabled"
        $this.FailRecommendation="Enable Unusual Characters Safety Tips so that users can receive visible indication on incoming messages."
        $this.Importance="Office 365 ATP can show a warning tip to recipients where the sender name or email address contains character sets that aren't usually used together."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://protection.office.com/antiphishing"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $PolicyExists = $False

        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}))
        {

            $PolicyExists = $True

            #  Determine if tips for user impersonation is on

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="EnableUnusualCharactersSafetyTips"
            $ConfigObject.ConfigData=$Policy.EnableUnusualCharactersSafetyTips

            If($Policy.EnableUnusualCharactersSafetyTips -eq $false)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")                         
            }

            $this.AddConfig($ConfigObject)

        }

        If($PolicyExists -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object="No Policies"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            

            $this.AddConfig($ConfigObject)      
        }             

    }

}