using module "..\ORCA.psm1"

class ORCA120_spam : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA120_spam()
    {
        $this.Control="120-spam"
        $this.Area="Zero Hour Autopurge"
        $this.Name="Zero Hour Autopurge Enabled for Spam"
        $this.PassText="Zero Hour Autopurge is Enabled"
        $this.FailRecommendation="Enable Zero Hour Autopurge"
        $this.Importance="Zero Hour Autopurge can assist removing false-negatives post detection from mailboxes. By default, it is enabled."
        $this.ExpandResults=$True
        $this.ItemName="Policy"
        $this.DataType="ZapEnabled Setting"
        $this.Links= @{
            "Zero-hour auto purge - protection against spam and malware"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/zero-hour-auto-purge"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {
            if($Policy.SpamZapEnabled -eq $true) {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.SpamZapEnabled)
                    Rule="ZAP Spam Enabled"
                    Control=$this.Control
                } 
            } else {
                $this.Results +=  New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.SpamZapEnabled)
                    Rule="ZAP Spam Disabled"
                    Control=$this.Control
                }
            }
        }        

    }

}