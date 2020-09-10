<#

Checks ATP Anti-phishing policy Advanced phishing thresholds 

#>

using module "..\ORCA.psm1"

class ORCA220 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA220()
    {
        $this.Control=220
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Advanced Phishing Threshold Level"
        $this.PassText="Advanced Phish filter Threshold level is adequate."
        $this.FailRecommendation="Set Advanced Phish filter Threshold to 2 or 3"
        $this.Importance="The higher the Advanced Phishing Threshold Level, the stricter the mechanisms are that detect phishing attempts against your users, however, too high may be considered too strict."
        $this.ExpandResults=$True
        $this.ItemName="Antiphishing Policy"
        $this.DataType="Advanced Phishing Threshold Level"
        $this.ChiValue=[ORCACHI]::Medium
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

        ForEach($Policy in $Config["AntiPhishPolicy"]) 
        {

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$($Policy.Name)
            $ConfigObject.ConfigData=$($Policy.PhishThresholdLevel)

            # Standard

            If($Policy.PhishThresholdLevel -eq 2)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            # Strict

            If($Policy.PhishThresholdLevel -eq 3)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            }

            $this.AddConfig($ConfigObject)


        }        

    }

}