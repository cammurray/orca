using module "..\ORCA.psm1"

class ORCA180 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA180()
    {
        $this.Control=180
        $this.Services=[ORCAService]::MDO
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="Anti-spoofing protection"
        $this.PassText="Anti-phishing policy exists and EnableSpoofIntelligence is true"
        $this.FailRecommendation="Enable anti-spoofing protection in Anti-phishing policy"
        $this.Importance="When the sender email address is spoofed, the message appears to originate from someone or somewhere other than the actual source. Anti-spoofing protection examines forgery of the 'From: header' which is the one that shows up in an email client like Outlook. It is recommended to enable anti-spoofing protection in Office 365 Anti-phishing policies."
        $this.ExpandResults=$True
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Antispoof Enforced"
        $this.ChiValue=[ORCACHI]::High
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.Links= @{
            "Microsoft 365 Defender Portal - Anti-phishing"="https://security.microsoft.com/antiphishing"
            "Anti-spoofing protection in Office 365"="https:/aka.ms/orca-atpp-docs-3"
            "Recommended settings for EOP and Microsoft Defender for Office 365"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
      
        ForEach($Policy in $Config["AntiPhishPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigItem="EnableSpoofIntelligence"
            $ConfigObject.ConfigData=$Policy.EnableSpoofIntelligence
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigDisabled = $IsPolicyDisabled
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Fail if Enabled or EnableSpoofIntelligence is not set to true in any policy
            If($Policy.EnableSpoofIntelligence -eq $true)
            {
                # Check objects
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

            }
            else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            $this.AddConfig($ConfigObject)

        }

        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableSpoofIntelligence"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }       

    }

}