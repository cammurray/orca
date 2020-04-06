using module "..\ORCA.psm1"

class ORCA141 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA141()
    {
        $this.Control=141
        $this.Area="Content Filter Policies"
        $this.Name="Bulk Action"
        $this.PassText="Bulk action set to Move message to Junk Email Folder"
        $this.FailRecommendation="Change bulk action to move messages to junk mail folder"
        $this.Importance="It is recommended to configure Bulk detection action to Move messages to Junk Email folder."
        $this.ExpandResults=$True
        $this.ItemName="Spam Policy"
        $this.DataType="Action"
        $this.Links= @{
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
            $ConfigObject.ConfigData=$($Policy.BulkSpamAction)

            # For standard Fail if BulkSpamAction is not set to MoveToJmf
    
            If($Policy.BulkSpamAction -ne "MoveToJmf") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            # For strict Fail if BulkSpamAction is not set to Quarantine

            If($Policy.BulkSpamAction -ne "Quarantine") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            
            $this.AddConfig($ConfigObject)

        }        

    }

}