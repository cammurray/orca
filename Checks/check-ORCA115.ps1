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
        $this.Links=@{
            "Set up Office 365 ATP anti-phishing and anti-phishing policies"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-anti-phishing-policies?view=o365-worldwide"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }   
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $true}))
        {

            #Determine if Mailbox Intelligence Protection is enabled

            If($Policy.EnableMailboxIntelligenceProtection -eq $false)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="EnableMailboxIntelligenceProtection"
                    ConfigData=$($Policy.EnableMailboxIntelligenceProtection)
                    Control=$this.Control
                }
            }
            Else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="EnableMailboxIntelligenceProtection"
                    ConfigData=$($Policy.EnableMailboxIntelligenceProtection)
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