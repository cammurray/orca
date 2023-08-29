using module "..\ORCA.psm1"

class ORCA241 : ORCACheck
{
    <#
    
        Check for first contact safety tip
    
    #>

    ORCA241()
    {
        $this.Control=241
        $this.Services=[ORCAService]::MDO
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="First Contact Safety Tip"
        $this.PassText="Anti-phishing policy exists and EnableFirstContactSafetyTips is true"
        $this.FailRecommendation="Enable fist contact safety tips to highlight suspicious messages to users."
        $this.Importance="Attackers pretend to be other people in order to trick users. By enabling first contact safety tips, users are shown a visual representation on the email that this is the first time that they have received an email from this sender. This can trigger users in to being suspicious of an email if it they believe it is coming from someone they know."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "First Contact Safety Tip"="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-about?view=o365-worldwide#first-contact-safety-tip"
            "Security & Compliance Center - Anti-phishing"="https://security.microsoft.com/antiphishing"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach ($Policy in $Config["AntiPhishPolicy"])
        {

            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableFirstContactSafetyTips"
            $ConfigObject.ConfigData=$Policy.EnableFirstContactSafetyTips
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($Policy.EnableFirstContactSafetyTips -eq $true)
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

        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableFirstContactSafetyTips"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }
    }

}