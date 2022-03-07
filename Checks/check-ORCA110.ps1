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
            "Security & Compliance Center - Anti-malware"="https://aka.ms/orca-mfp-action-antimalware"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["MalwareFilterPolicy"]).Count
        $CountOfPolicies = ($global:MalwarePolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["MalwareFilterPolicy"])
        {
            $IsPolicyDisabled = $false
            $EnableInternalSenderNotifications = $($Policy.EnableInternalSenderNotifications)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:MalwarePolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" + " [Disabled]"
                $EnableInternalSenderNotifications = "N/A"
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


            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$EnableInternalSenderNotifications
            
            If ($EnableInternalSenderNotifications -eq $False)
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                }
            }
            Else 
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                }
            }
            
            # Add config to check
            $this.AddConfig($ConfigObject)
        }
    }

}