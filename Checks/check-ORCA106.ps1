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
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $QuarantineRetentionPeriod = $($Policy.QuarantineRetentionPeriod)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$QuarantineRetentionPeriod
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset

            If($QuarantineRetentionPeriod -eq 30)
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