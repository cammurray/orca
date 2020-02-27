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
        $this.Links= @{
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
            If($Policy.PhishThresholdLevel -eq 1 -or $Policy.PhishThresholdLevel -eq 4)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.PhishThresholdLevel)
                    Rule="PhishThreshold Level is 1"
                    Control=$this.Control
                }
            } 
            else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.PhishThresholdLevel)
                    Rule="PhishThreshold Level 2 or higher"
                    Control=$this.Control
                }
            }
        }        

    }

}