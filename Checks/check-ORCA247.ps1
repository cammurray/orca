<#

247 User reported settings for Microsoft Teams

This check evaluates the org-wide Microsoft Teams user-reporting controls
called out in the Defender for Office 365 quick configuration guidance.

The check verifies the Teams messaging policy, Teams messaging configuration,
Teams calling policy, and the Defender user-reported settings policy using
the stable PowerShell surfaces documented by Microsoft. ORCA validates the
org-wide defaults only; custom policy assignment targeting is not resolved
here.

References:
    - https://learn.microsoft.com/defender-office-365/mdo-support-teams-quick-configure#step-4-defender-for-office-365-configure-user-reported-settings-for-microsoft-teams
    - https://learn.microsoft.com/defender-office-365/submissions-teams#user-reporting-settings-for-teams-items
    - https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox#use-exchange-online-powershell-to-configure-the-reported-message-settings
    - https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsmessagingpolicy
    - https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsmessagingconfiguration
    - https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamscallingpolicy
    - https://learn.microsoft.com/powershell/module/exchangepowershell/get-reportsubmissionpolicy

#>

using module "..\ORCA.psm1"

class ORCA247 : ORCACheck
{
    <#

        CONSTRUCTOR with Check Header Data

    #>

    ORCA247()
    {
        $this.Control=247
        $this.Services=[ORCAService]::MDO
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="User reported settings for Microsoft Teams"
        $this.PassText="Microsoft Teams user reported settings are enabled"
        $this.FailRecommendation="Enable the Microsoft Teams user reported settings recommended by Microsoft"
        $this.Importance="Microsoft Teams user reporting only works as intended when Teams messaging policy reporting is enabled, Teams messaging safety reporting is enabled, Teams calling policy reporting is enabled, and the Defender user-reported settings policy is configured for Teams message reporting. These controls let users report suspicious or incorrect Teams content and let defenders see those reports in the Microsoft Defender portal."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Teams and Defender policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Quickly configure Microsoft Teams protection in Defender for Office 365"="https://learn.microsoft.com/defender-office-365/mdo-support-teams-quick-configure#step-4-defender-for-office-365-configure-user-reported-settings-for-microsoft-teams"
            "User reported settings in Microsoft Teams"="https://learn.microsoft.com/defender-office-365/submissions-teams#user-reporting-settings-for-teams-items"
            "User reported settings"="https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox#use-exchange-online-powershell-to-configure-the-reported-message-settings"
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config)
    {
        # Validate the org-wide settings only. Teams policy assignments vary by
        # tenant and are not resolved in this lightweight check.

        if($null -ne $Config["TeamsMessagingPolicy"])
        {
            $Policy = $Config["TeamsMessagingPolicy"]
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Identity
            $ConfigObject.ConfigItem="AllowSecurityEndUserReporting"
            $ConfigObject.ConfigData=$Policy.AllowSecurityEndUserReporting

            if($Policy.AllowSecurityEndUserReporting -eq $true)
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

        if($null -ne $Config["TeamsMessagingConfiguration"])
        {
            $Configuration = $Config["TeamsMessagingConfiguration"]
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Configuration.Identity
            $ConfigObject.ConfigItem="ReportIncorrectSecurityDetections"
            $ConfigObject.ConfigData=$Configuration.ReportIncorrectSecurityDetections

            if($Configuration.ReportIncorrectSecurityDetections -eq "Enabled")
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

        if($null -ne $Config["TeamsCallingPolicy"])
        {
            $Policy = $Config["TeamsCallingPolicy"]
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Identity
            $ConfigObject.ConfigItem="ReportCall"
            $ConfigObject.ConfigData=$Policy.ReportCall

            if($Policy.ReportCall -eq $true)
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

        if($null -ne $Config["ReportSubmissionPolicy"])
        {
            $Policy = $Config["ReportSubmissionPolicy"]
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Identity
            $ConfigObject.ConfigItem="ReportChatMessageEnabled"
            $ConfigObject.ConfigData=$Policy.ReportChatMessageEnabled

            # The Defender portal selection is not mapped one-to-one to this
            # property, but this is the stable programmable signal Microsoft
            # exposes for Teams user-reported message handling.
            if($Policy.ReportChatMessageEnabled -eq $true)
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