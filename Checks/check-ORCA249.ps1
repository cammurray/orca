<#

249 Reject Direct Send

This check inspects the tenant-wide Exchange Online "Reject Direct Send"
toggle exposed by Get-OrganizationConfig as the RejectDirectSend property.

Direct send is the legacy SMTP submission path that lets a sender deliver
email to a recipient in one of your accepted domains over the public
smtp.office365.com / *.mail.protection.outlook.com endpoint without any
authentication, simply by addressing the message to an internal recipient.
It was historically used by on-premises multifunction devices and line of
business applications that needed to deliver to internal mailboxes, but
attackers have widely abused it to spoof internal-looking phishing because
the message bypasses sender authentication ownership checks for the
destination tenant.

When the tenant-wide RejectDirectSend toggle is set to $true, Exchange
Online refuses unauthenticated SMTP submissions targeted at the tenant's
own accepted domains. Tenants that have no remaining dependency on direct
send (for example, all line of business mail flow now goes through an
authenticated SMTP connector or a Microsoft Graph send-mail call) should
turn this on to remove the abuse vector.

Because some tenants still rely on direct send for legitimate device or
application mail flow, this check is informational rather than a baseline
mandate. It surfaces the current value so admins can make an informed
decision to enable it once direct send is no longer in use.

References:
    - https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790
    - https://learn.microsoft.com/powershell/module/exchangepowershell/set-organizationconfig?view=exchange-ps#-rejectdirectsend

#>

using module "..\ORCA.psm1"

class ORCA249 : ORCACheck
{
    <#

        CONSTRUCTOR with Check Header Data

    #>

    ORCA249()
    {
        $this.Control=249
        $this.Services=[ORCAService]::EOP
        $this.Area="Transport"
        $this.Name="Reject Direct Send"
        $this.PassText="Direct send to the tenant's accepted domains is rejected"
        $this.FailRecommendation="If your tenant no longer relies on direct send for line of business application or device mail flow, set Set-OrganizationConfig -RejectDirectSend `$true to block unauthenticated SMTP submissions to your own domains"
        $this.Importance="Direct send lets a sender deliver email to your accepted domains over Exchange Online's public SMTP endpoint without authentication, simply by addressing the message to an internal recipient. Historically used by multifunction devices and line of business applications, it is now a common abuse vector for internal-looking phishing because the message bypasses the normal sender authentication checks for the destination tenant. Tenants that no longer need direct send should enable RejectDirectSend on the organization configuration to remove this abuse path. This recommendation is conditional - verify there are no remaining dependencies on unauthenticated SMTP submission to your domains before enabling it."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Tenant Setting"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Introducing more control over direct send in Exchange Online"="https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790"
            "Set-OrganizationConfig (-RejectDirectSend)"="https://learn.microsoft.com/powershell/module/exchangepowershell/set-organizationconfig?view=exchange-ps#-rejectdirectsend"
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config)
    {
        # OrganizationConfig is collected unconditionally for EOP, but guard
        # against the rare collection failure (e.g. cmdlet unavailable under
        # constrained role assignments) so the check is skipped cleanly.
        $OrgConfig = $Config["OrganizationConfig"]
        if($null -eq $OrgConfig)
        {
            return
        }

        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$OrgConfig.Identity
        $ConfigObject.ConfigItem="RejectDirectSend"
        $ConfigObject.ConfigData=$OrgConfig.RejectDirectSend

        # Pass when direct send is rejected; otherwise raise an informational
        # finding (not a Fail) because some tenants legitimately rely on
        # direct send for device / application mail flow and disabling it
        # would break that traffic. The verdict is the same at Standard and
        # Strict assessment levels.
        If($OrgConfig.RejectDirectSend -eq $true)
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
        }
        Else
        {
            $ConfigObject.InfoText = "Direct send is currently allowed. If your tenant no longer relies on unauthenticated SMTP submission from devices or applications to your own accepted domains, enable RejectDirectSend on the organization configuration to remove this abuse vector."
            $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
        }

        $this.AddConfig($ConfigObject)
    }

}
