<#

115 - Check ATP Phishing Mailbox Intelligence Protection is enabled 

#>

using module "..\ORCA.psm1"

class ORCA115 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA115()
    {
        $this.Control=115
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Mailbox Intelligence Protection"
        $this.PassText="Mailbox intelligence based impersonation protection is enabled in anti-phishing policies"
        $this.FailRecommendation="Enable Mailbox intelligence based impersonation protection in anti-phishing policies"
        $this.Importance="Mailbox Intelligence Protection enhances impersonation protection for users based on each user's individual sender graph."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links=@{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Set up Office 365 ATP anti-phishing and anti-phishing policies"="https://aka.ms/orca-atpp-docs-9"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }   
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $PolicyExists = $False
        
        #$CountOfPolicies = ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}).Count       
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        
        ForEach($Policy in ($Config["AntiPhishPolicy"]))
        {

            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableMailboxIntelligenceProtection = $($Policy.EnableMailboxIntelligenceProtection)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            $PolicyExists = $True

            # Determine if Mailbox Intelligence Protection is enabled

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableMailboxIntelligenceProtection"
            $ConfigObject.ConfigData=$EnableMailboxIntelligenceProtection
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset

            If($EnableMailboxIntelligenceProtection -eq $false)
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

            $ConfigObject.Object="No Enabled Policy"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            

            $this.AddConfig($ConfigObject)
        }

    }

}