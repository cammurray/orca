<#

116 - Check ATP Phishing Mailbox Intelligence Protection action is set Move to Junk for recommended and Quarantine for strict 

#>

using module "..\ORCA.psm1"

class ORCA116 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA116()
    {
        $this.Control=116
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Mailbox Intelligence Protection Action"
        $this.PassText="Mailbox intelligence based impersonation protection action set to move message to junk mail folder"
        $this.FailRecommendation="Change Mailbox intelligence based impersonation protection action to move message to junk mail folder"
        $this.Importance="Mailbox intelligence protection enhances impersonation protection for users based on each user's individual sender graph. Move messages that are caught to junk mail folder."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links=@{
            "Security & Compliance Center - Anti-phishing"="https://protection.office.com/antiphishing"
            "Set up Office 365 ATP anti-phishing and anti-phishing policies"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-anti-phishing-policies?view=o365-worldwide"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }   
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $PolicyExists = $False

        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $true}))
        {

            $PolicyExists = $True

            # Determine if Mailbox Intelligence Protection action is configured

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="MailboxIntelligenceProtectionAction"
            $ConfigObject.ConfigData=$($Policy.MailboxIntelligenceProtectionAction)
            
            # For standard, this should be MoveToJmf
            If($Policy.MailboxIntelligenceProtectionAction -ne "MoveToJmf")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")                         
            }

            # For strict, this should be Quarantine
            If($Policy.MailboxIntelligenceProtectionAction -ne "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")            
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")                         
            }

            # For either Delete or Quarantine we should raise an informational
            If($Policy.MailboxIntelligenceProtectionAction -eq "Delete" -or $Policy.MailboxIntelligenceProtectionAction -eq "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($Policy.MailboxIntelligenceProtectionAction) option may impact the users ability to release emails and may impact user experience."
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