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
        $this.Links= @{
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}))
        {

            # Determine Mailbox Intelligence is ON

            If($Policy.EnableMailboxIntelligence -eq $false)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="EnableMailboxIntelligence"
                    ConfigData=$($Policy.EnableMailboxIntelligence)
                    Rule="Mailbox Intelligence Off"
                    Control=$this.Control
                }                
            }
            Else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="EnableMailboxIntelligence"
                    ConfigData=$($Policy.EnableMailboxIntelligence)
                    Rule="Mailbox Intelligence On"
                    Control=$this.Control
                }                            
            }

        }

        If($this.Results.Count -eq 0)
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Fail"
                Object="All"
                ConfigItem="Enabled"
                ConfigData="False"
                Control=$this.Control
            }         
        }        

    }

}