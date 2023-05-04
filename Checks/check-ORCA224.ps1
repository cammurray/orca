<#

224 - Check ATP Phishing Similar Users Safety Tips 

#>

using module "..\ORCA.psm1"

class ORCA224 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA224()
    {
        $this.Control=224
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Similar Users Safety Tips"
        $this.PassText="Similar Users Safety Tips is enabled"
        $this.FailRecommendation="Enable Similar Users Safety Tips so that users can receive visible indication on incoming messages"
        $this.Importance="Office 365 ATP can show a warning tip to recipients in messages that might be from an impersonated user."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
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

        $PolicyExists = $False
        #$CountOfPolicies = ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}).Count
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in ($Config["AntiPhishPolicy"]))
        {

            $IsPolicyDisabled = $false
            $EnableSimilarUsersSafetyTips = $($Policy.EnableSimilarUsersSafetyTips)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:AntiSpamPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            $PolicyExists = $True

            #  Determine if tips for user impersonation is on

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableSimilarUsersSafetyTips"
            $ConfigObject.ConfigData=$EnableSimilarUsersSafetyTips
            $ConfigObject.ConfigDisabled = $IsPolicyDisabled
            $ConfigObject.ConfigReadonly = $Policy.IsPreset

            If($EnableSimilarUsersSafetyTips -eq $false)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")        
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")                       
            }

            $this.AddConfig($ConfigObject)

        }

        If($PolicyExists -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object="No Policies"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            

            $this.AddConfig($ConfigObject)      
        }             

    }

}