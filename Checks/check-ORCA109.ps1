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
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $AllowedSenders = $($Policy.AllowedSenders)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            if($null -eq $AllowedSenders)
            {
                $AllowedSenders = "No Sender Detected"
            }

            $ConfigObject.ConfigData = $AllowedSenders
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled

            <#
            
            Important! Do not apply read-only on preset/default policies here.
            
            #>

            If(($AllowedSenders).Count -eq 0 -or $AllowedSenders -eq "No Sender Detected")
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