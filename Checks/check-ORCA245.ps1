<#

245 Priority Account Protection

This check evaluates whether the tenant-wide "Priority account protection"
toggle is enabled for Microsoft Defender for Office 365 Plan 2 tenants.

Priority account protection is a differentiated layer of protection that
applies extra heuristics tuned for the mail flow patterns of company
executives (and other high-value targets) to accounts that have the
Priority account user tag applied. By default it is enabled on MDO Plan 2
tenants, but it can be turned off — which silently removes the additional
protections from any Priority account tagged users without changing the
visible per-policy configuration.

The setting is exposed via Get-EmailTenantSettings as the
EnablePriorityAccountProtection property. Recommended value: $true.

References:
    - https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection
    - https://learn.microsoft.com/microsoft-365/admin/setup/priority-accounts

#>

using module "..\ORCA.psm1"

class ORCA245 : ORCACheck
{
    <#

        CONSTRUCTOR with Check Header Data

    #>

    ORCA245()
    {
        $this.Control=245
        $this.Services=[ORCAService]::MDO
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="Priority Account Protection"
        $this.PassText="Priority account protection is enabled"
        $this.FailRecommendation="Enable priority account protection so that accounts tagged as Priority accounts receive the additional Defender for Office 365 protections"
        $this.Importance="Priority account protection applies additional Microsoft Defender for Office 365 heuristics, tuned for the mail flow of company executives and other high-value users, to mailboxes that have the Priority account user tag applied. These extra protections only take effect while the tenant-wide priority account protection toggle is enabled; if it is disabled, users tagged as Priority accounts silently lose the differentiated protection even though their tag and any user-tag based reporting remain in place. It is recommended to keep priority account protection enabled."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Tenant Setting"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Configure and review priority account protection"="https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection"
            "Manage and monitor priority accounts"="https://learn.microsoft.com/microsoft-365/admin/setup/priority-accounts"
            "Microsoft 365 Defender Portal - Priority account protection"="https://security.microsoft.com/securitysettings/priorityAccountProtection"
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config)
    {
        # EmailTenantSettings is only populated when the Get-EmailTenantSettings
        # cmdlet is available (newer ExchangeOnlineManagement modules) and the
        # tenant has MDO Plan 2. If we have no data, do not emit a result —
        # the check is not applicable to this tenant.
        $TenantSettings = $Config["EmailTenantSettings"]
        if($null -eq $TenantSettings)
        {
            return
        }

        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$TenantSettings.Identity
        $ConfigObject.ConfigItem="EnablePriorityAccountProtection"
        $ConfigObject.ConfigData=$TenantSettings.EnablePriorityAccountProtection

        # Priority account protection is a tenant-wide toggle; the recommended
        # value is the same for Standard and Strict assessment levels.
        If($TenantSettings.EnablePriorityAccountProtection -eq $true)
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
        }
        Else
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
        }

        $this.AddConfig($ConfigObject)
    }

}
