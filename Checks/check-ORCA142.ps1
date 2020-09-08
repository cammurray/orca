using module "..\ORCA.psm1"

class ORCA142 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA142()
    {
        $this.Control=142
        $this.Area="Anti-Spam Policies"
        $this.Name="Phish Action"
        $this.PassText="Phish action set to Quarantine message"
        $this.FailRecommendation="Change Phish action to Quarantine message"
        $this.Importance="It is recommended to configure the Phish detection action to Quarantine so that these emails are not visible to the end user from within Outlook. As Phishing emails are designed to look legitimate, users may mistakenly think that a phishing email in Junk is false-positive."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Action"
        $this.ChiValue=[ORCACHI]::VeryHigh
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
            $ConfigObject.ConfigData=$($Policy.PhishSpamAction)

            # Fail if PhishSpamAction is not set to Quarantine
    
            If($Policy.PhishSpamAction -eq "Quarantine") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            If($Policy.PhishSpamAction -eq "Delete" -or $Policy.PhishSpamAction -eq "Redirect")
            {
                # For either Delete or Quarantine we should raise an informational
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($Policy.PhishSpamAction) option may impact the users ability to release emails and may impact user experience."
            }


            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }        

    }

}