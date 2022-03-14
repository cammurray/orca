<#

ORCA-106 Checks if the Anti-Spam Filter Policy quarantine retention period is configured to 30 days.

#>

using module "..\ORCA.psm1"

class ORCA106 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA106()
    {
        $this.Control="ORCA-106"
        $this.Area="Anti-Spam Policies"
        $this.Name="Quarantine retention period"
        $this.PassText="Quarantine retention period is 30 days"
        $this.FailRecommendation="Configure the Quarantine retention period to 30 days"
        $this.Importance="You can view, release, download, delete and report false positive quarantined email messages or files captured by Advance Threat Protection (ATP) for SharePoint Online, OneDrive for Business, and Microsoft Teams in Office 365. Keep messages in the quarantine for 30 days to allow enough time for further investigation. This is the default value and also the maximum."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Filter Policy"
        $this.DataType="Quarantine Retention Period"
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Manage quarantined messages and files as an administrator in Office 365"="https://aka.ms/orca-antispam-docs-6"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            $IsPolicyDisabled = $false
            $QuarantineRetentionPeriod = $($Policy.QuarantineRetentionPeriod)

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
                $QuarantineRetentionPeriod = "N/A"
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
            $ConfigObject.ConfigData=$QuarantineRetentionPeriod

            If($QuarantineRetentionPeriod -eq 30)
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