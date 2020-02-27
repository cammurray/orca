using module "..\ORCA.psm1"

class ORCA104 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA104()
    {
        $this.Control="ORCA-104"
        $this.Area="Content Filter Policies"
        $this.Name="High Confidence Phish Action"
        $this.PassText="High Confidence Phish action set to Quarantine message"
        $this.FailRecommendation="Change High Confidence Phish action to Quarantine message"
        $this.Importance="It is recommended to configure the High Confidence Phish detection action to Quarantine so that these emails are not visible to the end user from within Outlook. As Phishing emails are designed to look legitimate, users may mistakenly think that a phishing email in Junk is false-positive."
        $this.ExpandResults=$True
        $this.ItemName="Spam Policy"
        $this.DataType="Action"
        $this.Links= @{
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        # Fail if HighConfidencePhishAction is not set to Quarantine

        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {
            If($Policy.HighConfidencePhishAction -ne "Quarantine") {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.HighConfidencePhishAction)
                    Rule="PhishSpamAction set to $($Policy.PhishSpamAction)"
                    Control=$this.Control
                } 
            } else {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.HighConfidencePhishAction)
                    Rule="PhishSpamAction set to $($Policy.PhishSpamAction)"
                    Control=$this.Control
                } 
            }
        }        

    }

}