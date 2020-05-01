using module "..\ORCA.psm1"

class ORCA140 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA140()
    {
        $this.Control=140
        $this.Area="Content Filter Policies"
        $this.Name="High Confidence Spam Action"
        $this.PassText="High Confidence Spam action set to Quarantine message"
        $this.FailRecommendation="Change High Confidence Spam action to Quarantine message"
        $this.Importance="It is recommended to configure High Confidence Spam detection action to Quarantine message."
        $this.ExpandResults=$True
        $this.ItemName="Spam Policy"
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

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Name
            $ConfigObject.ConfigItem=$($Policy.Name)
            $ConfigObject.ConfigData=$($Policy.HighConfidenceSpamAction)
    
            # Fail if HighConfidenceSpamAction is not set to Quarantine
    
            If($Policy.HighConfidenceSpamAction -eq "Quarantine") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            # If action is Delete pass as informational
            If($Policy.HighConfidenceSpamAction -eq "Delete")
            {
                $ConfigObject.InfoText = "The entire message is silently deleted, including all attachments and not availible in the quarantine."
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
            }
            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }        

    }

}