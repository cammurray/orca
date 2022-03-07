<#

116 - Check ATP Phishing Mailbox Intelligence Protection action is set Move to Junk for recommended and Quarantine for strict 

#>

using module "..\ORCA.psm1"

class ORCA116 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA116()
    {
        $this.Control=116
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Mailbox Intelligence Protection Action"
        $this.PassText="Mailbox intelligence based impersonation protection action set to move message to junk mail folder"
        $this.FailRecommendation="Change Mailbox intelligence based impersonation protection action to move message to junk mail folder"
        $this.Importance="Mailbox intelligence protection enhances impersonation protection for users based on each user's individual sender graph. Move messages that are caught to junk mail folder."
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
        #$CountOfPolicies = ($Config["AntiPhishPolicy"]| Where-Object {$_.Enabled -eq $true}).Count
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in ($Config["AntiPhishPolicy"] ))
        {

            $IsPolicyDisabled = $false
            $MailboxIntelligenceProtectionAction = $($Policy.MailboxIntelligenceProtectionAction)

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
                $MailboxIntelligenceProtectionAction = "N/A"
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

            # Determine if Mailbox Intelligence Protection action is configured

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="MailboxIntelligenceProtectionAction"
            $ConfigObject.ConfigData=$MailboxIntelligenceProtectionAction
            
            # For standard, this should be MoveToJmf
            If($MailboxIntelligenceProtectionAction -ne "MoveToJmf")
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

            # For strict, this should be Quarantine
            If($MailboxIntelligenceProtectionAction -ne "Quarantine")
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
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")  
                       }
                                        
            }

            # For either Delete or Quarantine we should raise an informational
            If($MailboxIntelligenceProtectionAction -eq "Delete" -or $MailboxIntelligenceProtectionAction -eq "Quarantine")
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
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($MailboxIntelligenceProtectionAction) option may impact the users ability to release emails and may impact user experience."
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