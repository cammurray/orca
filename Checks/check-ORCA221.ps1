<#

221 - Check ATP Phishing Mailbox Intelligence is enabled 

#>

using module "..\ORCA.psm1"

class ORCA221 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA221()
    {
        $this.Control=221
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Mailbox Intelligence Enabled"
        $this.PassText="Mailbox intelligence is enabled in anti-phishing policies"
        $this.FailRecommendation="Enable mailbox intelligence in anti-phishing policies"
        $this.Importance="Mailbox Intelligence checks can provide your users with intelligence on suspicious incoming emails that appear to be from users that they normally communicate with based on their graph."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
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

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="EnableMailboxIntelligence"
            $ConfigObject.ConfigData=$Policy.EnableMailboxIntelligence

            # Determine Mailbox Intelligence is ON

            If($Policy.EnableMailboxIntelligence -eq $false)
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
            $ConfigObject.Object="All"
            $ConfigObject.ConfigItem="EnableMailboxIntelligence"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")  

            $this.AddConfig($ConfigObject)
                 
        }        

    }

}