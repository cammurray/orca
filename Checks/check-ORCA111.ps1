using module "..\ORCA.psm1"

class ORCA111 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA111()
    {
        $this.Control="ORCA-111"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Unauthenticated Sender (tagging)"
        $this.PassText="Anti-phishing policy exists and EnableUnauthenticatedSender is true"
        $this.FailRecommendation="Enable unauthenticated sender tagging in Anti-phishing policy"
        $this.Importance="When the sender email address is spoofed, the message appears to originate from someone or somewhere other than the actual source. It is recommended to enable unauthenticated sender tagging in Office 365 Anti-phishing policies. The feature apply a '?' symbol in Outlook's sender card if the sender fails authentication checks."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://protection.office.com/antiphishing"
            "Unverified Sender"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/unverified-sender-feature"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach ($Policy in $Config["AntiPhishPolicy"])
        {

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="EnableUnauthenticatedSender"
            $ConfigObject.ConfigData=$($Policy.EnableUnauthenticatedSender)

            If(($Policy.Enabled -eq $true -and $Policy.EnableUnauthenticatedSender -eq $true) -or ($Policy.Identity -eq "Office365 AntiPhish Default" -and $Policy.EnableUnauthenticatedSender -eq $true))
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }        
    }

}