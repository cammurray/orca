<#

246 Zero-hour auto purge (ZAP) for Microsoft Teams

This check evaluates whether the tenant-wide ZAP toggle for Microsoft Teams
is enabled.

Microsoft guidance for Teams protection recommends that Zero-hour auto purge
(ZAP) for Teams is turned on so Defender for Office 365 can retroactively
remove malicious Teams content after updated detections.

The setting is exposed via Get-TeamsProtectionPolicy as ZapEnabled.
Recommended value: $true.

References:
    - https://learn.microsoft.com/defender-office-365/mdo-support-teams-quick-configure#step-3-defender-for-office-365-verify-zero-hour-auto-purge-zap-for-microsoft-teams
    - https://learn.microsoft.com/defender-office-365/mdo-support-teams-about#configure-zap-for-teams-protection-in-defender-for-office-365
    - https://learn.microsoft.com/powershell/module/exchangepowershell/get-teamsprotectionpolicy

#>

using module "..\ORCA.psm1"

class ORCA246 : ORCACheck
{
    <#

        CONSTRUCTOR with Check Header Data

    #>

    ORCA246()
    {
        $this.Control=246
        $this.Services=[ORCAService]::MDO
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="Zero-hour auto purge (ZAP) for Microsoft Teams"
        $this.PassText="Zero-hour auto purge (ZAP) for Microsoft Teams is enabled"
        $this.FailRecommendation="Enable Zero-hour auto purge (ZAP) for Microsoft Teams"
        $this.Importance="Zero-hour auto purge (ZAP) for Teams allows Defender for Office 365 to retroactively detect and neutralize malicious Teams messages after initial delivery. Keeping this tenant-wide setting enabled reduces dwell time for missed threats and helps limit end-user exposure to later-identified malicious content."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Teams Protection Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Microsoft 365 Defender Portal - Microsoft Teams protection"="https://security.microsoft.com/securitysettings/teamsProtectionPolicy"
            "Quickly configure Microsoft Teams protection in Defender for Office 365"="https://learn.microsoft.com/defender-office-365/mdo-support-teams-quick-configure#step-3-defender-for-office-365-verify-zero-hour-auto-purge-zap-for-microsoft-teams"
            "Configure ZAP for Teams protection in Defender for Office 365"="https://learn.microsoft.com/defender-office-365/mdo-support-teams-about#configure-zap-for-teams-protection-in-defender-for-office-365"
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config)
    {
        # TeamsProtectionPolicy is only populated when the
        # Get-TeamsProtectionPolicy cmdlet is available and the tenant
        # supports Microsoft Teams protection settings.
        $TeamsProtectionPolicies = $Config["TeamsProtectionPolicy"]
        if($null -eq $TeamsProtectionPolicies)
        {
            return
        }

        foreach($Policy in $TeamsProtectionPolicies)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Name
            $ConfigObject.ConfigItem="ZapEnabled"
            $ConfigObject.ConfigData=$Policy.ZapEnabled

            # Teams ZAP recommended state is enabled for both Standard and Strict.
            if($Policy.ZapEnabled -eq $true)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            }

            $this.AddConfig($ConfigObject)
        }

    }

}
