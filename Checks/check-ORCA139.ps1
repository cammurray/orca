using module "..\ORCA.psm1"

class ORCA139 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA139()
    {
        $this.Control=139
        $this.Area="Content Filter Policies"
        $this.Name="Spam Action"
        $this.PassText="Spam action set to move message to junk mail folder"
        $this.FailRecommendation="Change Spam action to Move message to Junk Email Folder"
        $this.Importance="It is recommended to configure Spam detection action to Move messages to Junk Email folder."
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
        $Check = "Content Filter Actions"

        $this.Results = @()
    
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
    
            # Fail if SpamAction is not set to MoveToJmf
    
            If($Policy.SpamAction -ne "MoveToJmf") 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Check=$Check
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.SpamAction)
                    Rule="SpamAction set to $($Policy.SpamAction)"
                    Control=$this.Control
                } 
            } 
            else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Check=$Check
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.SpamAction)
                    Rule="SpamAction set to $($Policy.SpamAction)"
                    Control=$this.Control
                } 
            }
    
        }        

    }

}