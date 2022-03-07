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
            "Security & Compliance Center - Anti-malware"="https://aka.ms/orca-mfp-action-antimalware"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
            "Configure anti-malware policies"="https://aka.ms/orca-mfp-docs-1"
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
            $EnableExternalSenderNotifications = $($Policy.EnableExternalSenderNotifications)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:MalwarePolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" +" [Disabled]"
                $EnableExternalSenderNotifications = "N/A"
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
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableExternalSenderNotifications"
            $ConfigObject.ConfigData=$EnableExternalSenderNotifications

            # Fail if EnableExternalSenderNotifications is set to true in the policy
            If($EnableExternalSenderNotifications -eq $true) 
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not properly set according to this check. It is being flagged incase of accidental enablement."
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
            Else
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

            $this.AddConfig($ConfigObject)

        }

    }

}