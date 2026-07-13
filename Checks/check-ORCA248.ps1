<#

248 User reported settings for Outlook (email)

Validates the org-wide user-reporting baseline that governs the built-in
Outlook Report button and the Defender user-submissions experience for
email. The settings are exposed by Get-ReportSubmissionPolicy on the
DefaultReportSubmissionPolicy object and configured in the Defender
portal at:

    https://security.microsoft.com/securitysettings/userSubmission

Three booleans drive the security-relevant baseline; everything else on
ReportSubmissionPolicy is UX text (pre/post submit pop-ups, branding) or
PII (reporting-mailbox addresses) and is intentionally not evaluated by
this check:

    1. EnableReportToMicrosoft                $true
       Microsoft-integrated reporting in Outlook is on, so user-reported
       messages are sent to Microsoft for analysis. In Defender for
       Office 365 Plan 2 this also triggers Automated Investigation and
       Response (AIR).

    2. DisableUserSubmissionOptions           $false
       "Monitor reported messages in Outlook" is selected. When this is
       turned off, the Outlook Report button is disabled tenant-wide and
       no other user-reported settings apply.

    3. DisableQuarantineReportingOption       $false
       Users can report messages from quarantine as they release them,
       so missed malicious mail still reaches Microsoft and the SecOps
       reporting mailbox.

Teams user reporting is covered separately by ORCA247.

References:
    - https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox
    - https://learn.microsoft.com/defender-office-365/submissions-outlook-report-messages
    - https://learn.microsoft.com/powershell/module/exchangepowershell/get-reportsubmissionpolicy
    - https://learn.microsoft.com/powershell/module/exchangepowershell/set-reportsubmissionpolicy

#>

using module "..\ORCA.psm1"

class ORCA248 : ORCACheck
{
    <#

        CONSTRUCTOR with Check Header Data

    #>

    ORCA248()
    {
        $this.Control=248
        $this.Services=[ORCAService]::EOP
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="User reported settings for Outlook"
        $this.PassText="Outlook user reported settings match the Microsoft baseline"
        $this.FailRecommendation="Enable Microsoft-integrated reporting in Outlook, keep the Outlook Report button enabled, and allow reporting from quarantine"
        $this.Importance="The Outlook Report button feeds user-reported messages back to Microsoft for analysis and, on Defender for Office 365 Plan 2, triggers Automated Investigation and Response (AIR). When EnableReportToMicrosoft is off, missed phishing and malware never reach Microsoft for re-evaluation. When DisableUserSubmissionOptions is true, the Outlook Report button is disabled tenant-wide and end users have no way to report suspicious mail. When DisableQuarantineReportingOption is true, users cannot report messages they release from quarantine. All three settings should match the Microsoft-recommended baseline."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Report Submission Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Microsoft Defender Portal - User reported settings"="https://security.microsoft.com/securitysettings/userSubmission"
            "User reported settings"="https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox"
            "Report suspicious email messages with the built-in Report button in Outlook"="https://learn.microsoft.com/defender-office-365/submissions-outlook-report-messages"
            "Set-ReportSubmissionPolicy cmdlet reference"="https://learn.microsoft.com/powershell/module/exchangepowershell/set-reportsubmissionpolicy"
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config)
    {
        # ReportSubmissionPolicy is populated only when the
        # Get-ReportSubmissionPolicy cmdlet is available (newer
        # ExchangeOnlineManagement builds). When it is unavailable the
        # collector sets it to $null and this check has nothing to evaluate.
        $Policy = $Config["ReportSubmissionPolicy"]
        if($null -eq $Policy)
        {
            return
        }

        # Single tenant-wide policy named DefaultReportSubmissionPolicy.
        # Defensive foreach covers any future multi-policy scenario without
        # changing the check shape.
        foreach($P in $Policy)
        {
            # ----- 1. EnableReportToMicrosoft -----
            # Recommended: $true. Sends user-reported messages to Microsoft
            # and (on MDO Plan 2) triggers AIR.
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$P.Identity
            $ConfigObject.ConfigItem="EnableReportToMicrosoft"
            $ConfigObject.ConfigData=$P.EnableReportToMicrosoft

            if($P.EnableReportToMicrosoft -eq $true)
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

            # ----- 2. DisableUserSubmissionOptions -----
            # Recommended: $false. Corresponds to the "Monitor reported
            # messages in Outlook" toggle in the Defender portal.
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$P.Identity
            $ConfigObject.ConfigItem="DisableUserSubmissionOptions"
            $ConfigObject.ConfigData=$P.DisableUserSubmissionOptions

            if($P.DisableUserSubmissionOptions -eq $false)
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

            # ----- 3. DisableQuarantineReportingOption -----
            # Recommended: $false. Lets users report messages from
            # quarantine when releasing them.
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$P.Identity
            $ConfigObject.ConfigItem="DisableQuarantineReportingOption"
            $ConfigObject.ConfigData=$P.DisableQuarantineReportingOption

            if($P.DisableQuarantineReportingOption -eq $false)
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
