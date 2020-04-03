<#

ORCA-107 Check if End-user Spam notification is enabled and the notification frequency is 3 days

#>

using module "..\ORCA.psm1"

class ORCA107 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA107()
    {
        $this.Control="ORCA-107"
        $this.Area="Content Filter Policies"
        $this.Name="End-user Spam notifications"
        $this.PassText="End-user Spam notification is enabled and the frequency is set to 3 days"
        $this.FailRecommendation="Enable End-user Spam notification and set the frequency to 3 days"
        $this.Importance="Enable End-user Spam notifications to let users manage their own spam-quarantined messages (Release, Block sender, Review). End-user spam notifications contain a list of all spam-quarantined messages that the end-user has received during a time period."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Content Filter Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Configure end-user spam notifications in Exchange Online"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-end-user-spam-notifications-in-exchange-online"
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

            <#
            
            EnableEndUserSpamNotifications
            
            #>
            
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="EnableEndUserSpamNotifications"
                $ConfigObject.ConfigData=$($Policy.EnableEndUserSpamNotifications)
        
                If($Policy.EnableEndUserSpamNotifications -eq $true)
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                }
                Else 
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                }
                
                # Add config to check
                $this.AddConfig($ConfigObject)

            <#
            
            EndUserSpamNotificationFrequency
            
            #>
            
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="EndUserSpamNotificationFrequency"
                $ConfigObject.ConfigData=$($Policy.EndUserSpamNotificationFrequency)
        
                    
                If($Policy.EndUserSpamNotificationFrequency -eq 3)
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