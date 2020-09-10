using module "..\ORCA.psm1"

class ORCA223 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA223()
    {
        $this.Control=223
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="User Impersonation Action"
        $this.PassText="User impersonation action is set to move to Quarantine"
        $this.FailRecommendation="Configure user impersonation action to Quarantine"
        $this.Importance="User impersonation protection can detect spoofing of your sensitive users. Move messages that are caught using user impersonation detection to Quarantine."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Action"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://protection.office.com/antiphishing"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
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

            # Is enabled

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="EnableTargetedUserProtection"
            $ConfigObject.ConfigData=$Policy.EnableTargetedUserProtection

            If($Policy.EnableTargetedUserProtection -eq $False)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            
            $this.AddConfig($ConfigObject)

            # Action

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="TargetedUserProtectionAction"
            $ConfigObject.ConfigData=$Policy.TargetedUserProtectionAction

            If($Policy.TargetedUserProtectionAction -eq "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            If($Policy.TargetedUserProtectionAction -eq "Delete" -or $Policy.TargetedUserProtectionAction -eq "Redirect")
            {
                # For either Delete or Quarantine we should raise an informational
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($Policy.TargetedUserProtectionAction) option may impact the users ability to release emails and may impact user experience."
            }

            
            $this.AddConfig($ConfigObject)

        }
    
        If($PolicyExists -eq $False)
        {

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object="All"
            $ConfigObject.ConfigItem="Enabled"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

            $this.AddConfig($ConfigObject)
         
        }    

    }

}