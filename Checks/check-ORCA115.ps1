<#

115 - Check ATP Phishing Mailbox Intelligence Protection is enabled 

#>

using module "..\ORCA.psm1"

class ORCA115 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA115()
    {
        $this.Control=115
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Mailbox Intelligence Protection"
        $this.PassText="Mailbox intelligence based impersonation protection is enabled in anti-phishing policies"
        $this.FailRecommendation="Enable Mailbox intelligence based impersonation protection in anti-phishing policies"
        $this.Importance="Mailbox Intelligence Protection enhances impersonation protection for users based on each user's individual sender graph."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links=@{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Set up Office 365 ATP anti-phishing and anti-phishing policies"="https://aka.ms/orca-atpp-docs-9"
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
            $EnableMailboxIntelligenceProtection = $($Policy.EnableMailboxIntelligenceProtection)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:AntiSpamPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" +" [Disabled]"
                $EnableMailboxIntelligenceProtection = "N/A"
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

            # Determine if Mailbox Intelligence Protection is enabled

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableMailboxIntelligenceProtection"
            $ConfigObject.ConfigData=$EnableMailboxIntelligenceProtection

            If($EnableMailboxIntelligenceProtection -eq $false)
            {
                if($IsPolicyDisabled)
                    {
                        $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    elseif($IsBuiltIn)
                    {
                        $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    else
                       {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail") 
                       }           
            }
            Else 
            {
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
            }

            $this.AddConfig($ConfigObject)

        }
        
        If($PolicyExists -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object="No Enabled Policy"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            

            $this.AddConfig($ConfigObject)
        }

    }

}