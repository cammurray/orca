using module "..\ORCA.psm1"

class ORCA139 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA139()
    {
        $this.Control=139
        $this.Area="Anti-Spam Policies"
        $this.Name="Spam Action"
        $this.PassText="Spam action set to move message to junk mail folder or quarantine"
        $this.FailRecommendation="Change Spam action to move message to Junk Email Folder"
        $this.Importance="It is recommended to configure Spam detection action to Move messages to Junk Email folder."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Action"
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://protection.office.com/antispam"
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

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$($Policy.Name)
            $ConfigObject.ConfigData=$($Policy.SpamAction)

            # For standard, this should be MoveToJmf
            If($Policy.SpamAction -ne "MoveToJmf") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            # For strict, this should be Quarantine
            If($Policy.SpamAction -ne "Quarantine") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }

            # For either Delete or Redirect we should raise an informational
            If($Policy.SpamAction -eq "Delete" -or $Policy.SpamAction -eq "Redirect")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($Policy.SpamAction) option may impact the users ability to release emails and may impact user experience."
            }
            
            $this.AddConfig($ConfigObject)
            
        }        

    }

}