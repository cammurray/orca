<#

125 Checks if EOP anti-malware Policy external sender notification is configured.

#>

using module "..\ORCA.psm1"

class ORCA125 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA125()
    {
        $this.Control=125
        $this.Area="Malware Filter Policy"
        $this.Name="External Sender Notifications"
        $this.PassText="External Sender notifications are disabled"
        $this.FailRecommendation="Disable notifying external senders of malware detection"
        $this.Importance="Notifying external senders about malware detected in email messages could have negative impact. An adversary may use this information to verify effectiveness of malware detection."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Security & Compliance Center - Anti-malware"="aka.ms/orca-mfp-action-antimalware"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
            "Configure anti-malware policies"="https://aka.ms/orca-mfp-docs-1"
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
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="EnableExternalSenderNotifications"
            $ConfigObject.ConfigData=$($Policy.EnableExternalSenderNotifications)

            # Fail if EnableExternalSenderNotifications is set to true in the policy
            If($Policy.EnableExternalSenderNotifications -eq $true) 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            $this.AddConfig($ConfigObject)

        }

    }

}