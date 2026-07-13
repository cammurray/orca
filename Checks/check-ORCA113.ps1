using module "..\ORCA.psm1"

class ORCA113 : ORCACheck
{
    <#
    
        Check if AllowClickThrough is disabled in the organisation wide SafeLinks policy and if AllowClickThrough is True in SafeLink policies
    
    #>

    ORCA113()
    {
        $this.Control="ORCA-113"
        $this.Services=[ORCAService]::MDO
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="Do not let users click through safe links"
        $this.PassText="AllowClickThrough is disabled in Safe Links policies"
        $this.FailRecommendation="Do not let users click through safe links to original URL"
        $this.Importance="Microsoft Defender for Office 365 Safe Links can help protect your organization by providing time-of-click verification of  web addresses (URLs) in email messages and Office documents. It is possible to allow users click through Safe Links to the original URL. It is recommended to configure Safe Links policies to not let users click through safe links. "
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Microsoft 365 Defender Portal - Safe links"="https://security.microsoft.com/safelinksv2"
            "Microsoft Defender for Office 365 Safe Links policies"="https://aka.ms/orca-atpp-docs-11"
            "Recommended settings for EOP and Microsoft Defender for Office 365"="https://aka.ms/orca-atpp-docs-8"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $PolicyCount = 0
       
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {    
            $PolicyState = $Config["PolicyStates"][$Policy.Guid.ToString()]
            $IsPolicyDisabled = !$PolicyState.Applies
            $AllowClickThrough = $($Policy.AllowClickThrough)

            # Count the policy when it is enabled or when it is the built-in
            # protection policy. Built-in policy rows are shown for awareness,
            # but they are read-only and should not surface as recommendations.
            if(!$IsPolicyDisabled -or $PolicyState.BuiltIn)
            {
                $PolicyCount++
            }

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$PolicyState.Name
            $ConfigObject.ConfigItem="AllowClickThrough"
            $ConfigObject.ConfigData=$AllowClickThrough
            $ConfigObject.ConfigDisabled = $PolicyState.Disabled
            $ConfigObject.ConfigWontApply = !$PolicyState.Applies
            $ConfigObject.ConfigReadonly = $PolicyState.BuiltIn -or $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Built-in Safe Links policies are read-only. Surface them as
            # informational so admins understand the current state without
            # treating the row as a fixable recommendation.
            if($PolicyState.BuiltIn)
            {
                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. It is being shown for informational purposes only."
                $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
            }
            # Determine if AllowClickThrough is True in safelinks policies
            elseif($Policy.AllowClickThrough -eq $false)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")                 
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
        }

        if($PolicyCount -eq 0)
        {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object="All non-built in policies"
                $ConfigObject.ConfigItem="AllowClickThrough"
                $ConfigObject.ConfigData="Disabled"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                $this.AddConfig($ConfigObject)
        }

    }

}