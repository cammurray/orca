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
        $this.PassText="Mailbox intelligence based impersonation protection action set to move message to junk mail folder or quarantine"
        $this.FailRecommendation="Change Mailbox intelligence based impersonation protection action to move message to junk mail folder or quarantine."
        $this.Importance="Mailbox intelligence protection enhances impersonation protection for users based on each user's individual sender graph. Move messages that are caught to junk mail folder or quarantine."
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