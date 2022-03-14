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
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"] ).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
      
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            $IsPolicyDisabled = $false
            $SpamQuarantineTag =  $($Policy.SpamQuarantineTag)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:HostedContentPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" + " [Disabled]"
            }
            elseif($policyname -match "Built-In" -and $CountOfPolicies -gt 1)
            {
                $IsBuiltIn =$True
                $policyname = "$policyname" +" [Built-In]"
            }
            elseif(($policyname -eq "Default" -or $policyname -eq "Office365 AntiPhish Default") -and $CountOfPolicies -gt 1)
            {
                $IsBuiltIn =$True
                $policyname = "$policyname" +" [Default]"
            }


            <#
            
            EnableEndUserSpamNotifications
            
            #>
            
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$policyname
                $QuarantineTag = $SpamQuarantineTag
                $status = $false 
                $frequency =0
                ForEach($Tag in $Config["QuarantineTag"])
                {
                    if($($Tag.Name) -eq $QuarantineTag)
                    {
                        $status = $Tag.ESNEnabled
                        $frequency = $Tag.AdminNotificationFrequencyInDays

                        $ConfigObject.ConfigItem="EnableEndUserSpamNotifications"
                        
        
                        If($status -eq $false )
                        {

                            if($IsPolicyDisabled)
                            {
                                $ConfigObject.ConfigData ="N/A"
                                $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                            }
                            elseif($IsBuiltIn)
                            {
                                $ConfigObject.ConfigData = $status
                                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                            }
                            else
                            {
                                $ConfigObject.ConfigData = $status
                                 $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                            }
                        }
                        Else 
                        {
                            if($IsPolicyDisabled)
                            {
                                $ConfigObject.ConfigData = "N/A"
                                $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                            }
                            elseif($IsBuiltIn)
                            {
                                $ConfigObject.ConfigData = $status
                                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                            }
                            else
                            {
                                $ConfigObject.ConfigData = $status
                                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                            }
                        }
                
                        # Add config to check
                        $this.AddConfig($ConfigObject)

                        <#           
                            EndUserSpamNotificationFrequency           
                        #>
            
                        # Check objects
                        $ConfigObject = [ORCACheckConfig]::new()
                        $ConfigObject.Object = $policyname
                        $ConfigObject.ConfigItem = "EndUserSpamNotificationFrequency"
                        
        
                    
                        If($frequency -le 3)
                        {
                            if($IsPolicyDisabled)
                            {
                                $ConfigObject.ConfigData = "N/A"
                                $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                            }
                            elseif($IsBuiltIn)
                            {
                                $ConfigObject.ConfigData = $frequency
                                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                            }
                            else
                            {
                                $ConfigObject.ConfigData = $frequency
                                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                            }
                        }
                        Else 
                        {
                            if($IsPolicyDisabled)
                            {
                                $ConfigObject.ConfigData = "N/A"
                                $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                            }
                            elseif($IsBuiltIn)
                            {
                                $ConfigObject.ConfigData = $frequency
                                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                            }
                            else
                            {
                                $ConfigObject.ConfigData = $frequency
                                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                            }
                        }
                        # Add config to check
                        $this.AddConfig($ConfigObject)
                    }
                }
        }            
    }

}