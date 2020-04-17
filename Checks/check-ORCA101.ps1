using module "..\ORCA.psm1"

class ORCA101 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA101()
    {
        $this.Control="ORCA-101"
        $this.Area="Content Filter Policies"
        $this.Name="Mark Bulk as Spam"
        $this.PassText="Bulk is marked as spam"
        $this.FailRecommendation="Set the content filter policy to mark bulk mail as spam"
        $this.Importance="The differentiation between bulk and spam can sometimes be subjective. The bulk complaint level is based on the number of complaints from the sender. Marking bulk as spam can decrease the amount of perceived spam received. This setting is only available in PowerShell."
        $this.ExpandResults=$True
        $this.ItemName="Content Filter Policy"
        $this.DataType="Mark as Spam Bulk Mail Setting (MarkAsSpamBulkMail)"
        $this.Links= @{
            "Set-HostedContentFilterPolicy"="https://docs.microsoft.com/en-us/powershell/module/exchange/antispam-antimalware/set-hostedcontentfilterpolicy?view=exchange-ps"
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
            $ConfigObject.ConfigData=$($Policy.MarkAsSpamBulkMail)

            If($Policy.MarkAsSpamBulkMail -eq "On")
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