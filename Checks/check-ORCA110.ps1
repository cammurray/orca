<#

ORCA-110 Check if internal malware notification is disabled in malware policies.    

#>

using module "..\ORCA.psm1"

class ORCA110 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA110()
    {
        $this.Control="ORCA-110"
        $this.Area="Malware Filter Policy"
        $this.Name="Internal Sender Notifications"
        $this.PassText="Internal Sender notifications are disabled"
        $this.FailRecommendation="Disable notifying internal senders of malware detection"
        $this.Importance="Notifying internal senders about malware detected in email messages could have negative impact. An adversary with access to an already compromised mailbox may use this information to verify effectiveness of malware detection."
        $this.ExpandResults=$True
        $this.ItemName="Malware Policy"
        $this.DataType="EnableInternalSenderNotifications"
        $this.Links= @{
            "Security & Compliance Center - Anti-malware"="aka.ms/orca-mfp-action-antimalware"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["MalwareFilterPolicy"])
        {

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$($Policy.Name)
            $ConfigObject.ConfigData=$($Policy.EnableInternalSenderNotifications)
            
            If ($Policy.EnableInternalSenderNotifications -eq $False)
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