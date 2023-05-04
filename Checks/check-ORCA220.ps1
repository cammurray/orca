<#

Checks ATP Anti-phishing policy Advanced phishing thresholds 

#>

using module "..\ORCA.psm1"

class ORCA220 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA220()
    {
        $this.Control=220
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Advanced Phishing Threshold Level"
        $this.PassText="Advanced Phish filter Threshold level is adequate."
        $this.FailRecommendation="Set Advanced Phish filter Threshold to 2 or 3"
        $this.Importance="The higher the Advanced Phishing Threshold Level, the stricter the mechanisms are that detect phishing attempts against your users, however, too high may be considered too strict."
        $this.ExpandResults=$True
        $this.ItemName="Antiphishing Policy"
        $this.DataType="Advanced Phishing Threshold Level"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["AntiPhishPolicy"]).Count
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in $Config["AntiPhishPolicy"]) 
        {
            $IsPolicyDisabled = $false
            $PhishThresholdLevel = $($Policy.PhishThresholdLevel)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:AntiSpamPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$PhishThresholdLevel
            $ConfigObject.ConfigDisabled = $IsPolicyDisabled
            $ConfigObject.ConfigReadonly = $Policy.IsPreset

            # Standard

            If($PhishThresholdLevel -eq 2)  
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            # Strict

            If($PhishThresholdLevel -eq 3)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            }

            $this.AddConfig($ConfigObject)


        }        

    }

}