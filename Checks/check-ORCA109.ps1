<#

ORCA-109 Checks if the allowed senders list is empty in Anti-spam policies

#>

using module "..\ORCA.psm1"

class ORCA109 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA109()
    {
        $this.Control="ORCA-109"
        $this.Area="Content Filter Policies"
        $this.Name="Allowed Senders"
        $this.PassText="Senders are not being whitelisted in an unsafe manner"
        $this.FailRecommendation="Remove whitelisting on senders"
        $this.Importance="Emails coming from whitelisted senders bypass several layers of protection within Exchange Online Protection. If senders are whitelisted, they are open to being spoofed from malicious actors."
        $this.ExpandResults=$True
        $this.ItemName="Policy"
        $this.DataType="Setting"
        $this.Links= @{
            "Use Anti-Spam Policy Sender/Domain Allow lists"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/create-safe-sender-lists-in-office-365#use-anti-spam-policy-senderdomain-allow-lists"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            If(($Policy.AllowedSenders).Count -gt 0)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.AllowedSenders)
                    Control=$this.Control
                }
            }
            Else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    ConfigItem=$($Policy.Name)
                    ConfigData="0 Allowed Senders"
                    Control=$this.Control
                }
            }
        }        
    }

}