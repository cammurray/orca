using module "..\ORCA.psm1"

class ORCA111 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA111()
    {
        $this.Control="ORCA-111"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Unauthenticated Sender (tagging)"
        $this.PassText="Anti-phishing policy exists and EnableUnauthenticatedSender is true"
        $this.FailRecommendation="Enable unauthenticated sender tagging in Anti-phishing policy"
        $this.Importance="When the sender email address is spoofed, the message appears to originate from someone or somewhere other than the actual source. It is recommended to enable unauthenticated sender tagging in Office 365 Anti-phishing policies. The feature apply a '?' symbol in Outlook's sender card if the sender fails authentication checks."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Unverified Sender"="https://aka.ms/orca-atpp-docs-12"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["AntiPhishPolicy"] ).Count
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach ($Policy in $Config["AntiPhishPolicy"])
        {

            $IsPolicyDisabled = $false
            $EnableUnauthenticatedSender = $($Policy.EnableUnauthenticatedSender)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)
            $identity = $($Policy.Identity)
            $enabled = $($Policy.Enabled)

            ForEach($data in ($global:AntiSpamPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" + " [Disabled]"
                $EnableUnauthenticatedSender = "N/A"
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

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableUnauthenticatedSender"
            $ConfigObject.ConfigData=$EnableUnauthenticatedSender

            If(($enabled -eq $true -and $EnableUnauthenticatedSender -eq $true) -or ($identity -eq "Office365 AntiPhish Default" -and $EnableUnauthenticatedSender -eq $true))
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
            Else 
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
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }        
    }

}