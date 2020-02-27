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
    
            # Fail if HighConfidenceSpamAction is not set to Quarantine
    
            If($Policy.HighConfidenceSpamAction -ne "Quarantine") 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Check=$Check
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.HighConfidenceSpamAction)
                    Rule="HighConfidenceSpamAction set to $($Policy.HighConfidenceSpamAction)"
                    Control=$this.Control
                } 
            } 
            else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Check=$Check
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.HighConfidenceSpamAction)
                    Rule="HighConfidenceSpamAction set to $($Policy.HighConfidenceSpamAction)"
                    Control=$this.Control
                } 
            }
            
        }        

    }

}