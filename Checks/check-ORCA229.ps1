<#

ORCA-229 - Check allowed domains in ATP Anti-phishing policies 

#>

using module "..\ORCA.psm1"

class ORCA229 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA229()
    {
        $this.Control=229
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Anti-phishing trusted domains"
        $this.PassText="No trusted domains in Anti-phishing policy"
        $this.FailRecommendation="Remove whitelisting on domains in Anti-phishing policy"
        $this.Importance="Adding domains as trusted in Anti-phishing policy will result in the action for protected domains, protected users or mailbox intelligence protection will be not applied to messages coming from these sender domains. If a trusted domain needs to be added based on organizational requirements it should be reviewed regularly and updated as needed. We also do not recommend adding domains from shared services."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
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
        #$CountOfPolicies = ($Config["AntiPhishPolicy"]| Where-Object {$_.Enabled -eq $True}).Count
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in ($Config["AntiPhishPolicy"] ))
        {

            $IsPolicyDisabled = $false
            $ExcludedDomains = $($Policy.ExcludedDomains)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:MalwarePolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" +" [Disabled]"
            }
            elseif($policyname -match "Built-In" -and $CountOfPolicies -gt 1)
            {
                $IsBuiltIn =$True
                $policyname = "$policyname" +" [Built-In]"
            }
            elseif(($policyname -eq "Default" -or $policyname -eq "Office365 AntiPhish Default") -and $CountOfPolicies -gt 1)
            {
                $IsBuiltIn =$True
                $policyname = "$policyname" +" [Default]"
            }

            $PolicyExists = $True
            If(($ExcludedDomains).Count -gt 0)
            {
                ForEach($Domain in $ExcludedDomains) 
                {
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="ExcludedDomains"
                    $ConfigObject.ConfigData=$($Domain)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    $this.AddConfig($ConfigObject)  
                }
            }
            else 
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="ExcludedDomains"
                $ConfigObject.ConfigData="No domain detected"
                if($IsPolicyDisabled)
                {
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                   }
                $this.AddConfig($ConfigObject)  
            }
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