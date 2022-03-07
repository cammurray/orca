using module "..\ORCA.psm1"

class ORCA112 : ORCACheck
{
    <#
    
        Check if the Anti-spoofing policy action is configured to Move message to the recipients' Junk Email folder as per Standard security settings for Office 365 EOP/ATP
    
    #>

    ORCA112()
    {
        $this.Control="ORCA-112"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Anti-spoofing protection action"
        $this.PassText="Anti-spoofing protection action is configured to Move message to the recipients' Junk Email folders in Anti-phishing policy"
        $this.FailRecommendation="Configure Anti-spoofing protection action to Move message to the recipients' Junk Email folders in Anti-phishing policy"
        $this.Importance="When the sender email address is spoofed, the message appears to originate from someone or somewhere other than the actual source. With Standard security settings it is recommended to configure Anti-spoofing protection action to Move message to the recipients' Junk Email folders in Office 365 Anti-phishing policies."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Configuring the anti-spoofing policy"="https://aka.ms/orca-atpp-docs-5"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["AntiPhishPolicy"]).Count
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach ($Policy in $Config["AntiPhishPolicy"])
        {
            $IsPolicyDisabled = $false
            $AuthenticationFailAction = $($Policy.AuthenticationFailAction)

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
                $AuthenticationFailAction = "N/A"
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
            $ConfigObject.ConfigItem="AuthenticationFailAction"
            $ConfigObject.ConfigData=$AuthenticationFailAction
            
            If(($enabled -eq $true -and $AuthenticationFailAction -eq "MoveToJmf") -or ($identity -eq "Office365 AntiPhish Default" -and $AuthenticationFailAction -eq "MoveToJmf"))
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

            If(($enabled -eq $true -and $AuthenticationFailAction -eq "Quarantine") -or ($identity -eq "Office365 AntiPhish Default" -and $AuthenticationFailAction -eq "Quarantine"))
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
                    $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
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
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
                }
            }
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }        

    }

}