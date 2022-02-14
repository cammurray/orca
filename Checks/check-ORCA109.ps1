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
        $this.Area="Anti-Spam Policies"
        $this.Name="Allowed Senders"
        $this.PassText="Senders are not being whitelisted in an unsafe manner"
        $this.FailRecommendation="Remove whitelisting on senders"
        $this.Importance="Emails coming from whitelisted senders bypass several layers of protection within Exchange Online Protection. If senders are whitelisted, they are open to being spoofed from malicious actors."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Allowed Senders"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Use Anti-Spam Policy Sender/Domain Allow lists"="https://aka.ms/orca-antispam-docs-4"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$($Policy.Name)
            $ConfigObject.ConfigData=$($Policy.AllowedSenders)

            If(($Policy.AllowedSenders).Count -eq 0)
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