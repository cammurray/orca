using module "..\ORCA.psm1"

class ORCA142 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA142()
    {
        $this.Control=142
        $this.Area="Content Filter Policies"
        $this.Name="Phish Action"
        $this.PassText="Phish action set to Quarantine message"
        $this.FailRecommendation="Change Phish action to Quarantine message"
        $this.Importance="It is recommended to configure the Phish detection action to Quarantine so that these emails are not visible to the end user from within Outlook. As Phishing emails are designed to look legitimate, users may mistakenly think that a phishing email in Junk is false-positive."
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
    
            # Fail if PhishSpamAction is not set to Quarantine
    
            If($Policy.PhishSpamAction -ne "Quarantine") 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Check=$Check
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.PhishSpamAction)
                    Rule="PhishSpamAction set to $($Policy.PhishSpamAction)"
                    Control=$this.Control
                } 
            } 
            else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Check=$Check
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.PhishSpamAction)
                    Rule="PhishSpamAction set to $($Policy.PhishSpamAction)"
                    Control=$this.Control
                } 
            }
            
        }        

    }

}