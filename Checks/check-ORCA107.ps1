<#

ORCA-107 Check if End-user Spam notification is enabled and the notification frequency is less than equal to 3 days

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
        $this.Area="Anti-Spam Policies"
        $this.Name="End-user Spam notifications"
        $this.PassText="End-user Spam notification is enabled and the frequency is set to less than or equal to 3 days"
        $this.FailRecommendation="Enable End-user Spam notification and set the frequency to less than or equal to 3 days"
        $this.Importance="Enable End-user Spam notifications to let users manage their own spam-quarantined messages (Release, Block sender, Review). End-user spam notifications contain a list of all spam-quarantined messages that the end-user has received during a time period."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Anti-Spam Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Configure end-user spam notifications in Exchange Online"="https://aka.ms/orca-antispam-docs-2"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
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
                $QuarantineTag = $($Policy.SpamQuarantineTag)
                $status = $false 
                $frequency =0
                ForEach($Tag in $Config["QuarantineTag"])
                {
                    if($($Tag.Name) -eq $QuarantineTag)
                    {
                        $status = $Tag.ESNEnabled
                        $frequency = $Tag.AdminNotificationFrequencyInDays

                        $ConfigObject.ConfigItem="EnableEndUserSpamNotifications"
                        $ConfigObject.ConfigData = $status
        
                        If($status -eq $false )
                        {
                             $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                        }
                        Else 
                        {
                            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
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
                        $ConfigObject.ConfigData=$frequency
        
                    
                        If($frequency -le 3)
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
    }

}