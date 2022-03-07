using module "..\ORCA.psm1"

class ORCA222 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA222()
    {
        $this.Control=222
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Domain Impersonation Action"
        $this.PassText="Domain Impersonation action is set to move to Quarantine"
        $this.FailRecommendation="Configure domain impersonation action to Quarantine"
        $this.Importance="Domain Impersonation can detect impersonation attempts against your domains or domains that look very similiar to your domains. Move messages that are caught using this impersonation protection to Quarantine."
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
        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}))
        {
            $IsPolicyDisabled = $false
            $EnableTargetedDomainsProtection = $($Policy.EnableTargetedDomainsProtection)
            $EnableOrganizationDomainsProtection = $($Policy.EnableOrganizationDomainsProtection)
            $TargetedDomainProtectionAction = $($Policy.TargetedDomainProtectionAction)

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
                $EnableTargetedDomainsProtection = "N/A"
                $EnableOrganizationDomainsProtection = "N/A"
                $TargetedDomainProtectionAction = "N/A"
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

            <#
            
            EnableTargetedDomainsProtection / EnableOrgainizationDomainsProtection
            
            #>

            If($EnableTargetedDomainsProtection -eq $False -and $EnableOrganizationDomainsProtection -eq $False)
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()

                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="EnableTargetedDomainsProtection"
                $ConfigObject.ConfigData=$EnableTargetedDomainsProtection
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

                $this.AddConfig($ConfigObject)
                
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()

                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="EnableOrganizationDomainsProtection"
                $ConfigObject.ConfigData=$EnableOrganizationDomainsProtection
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
                $this.AddConfig($ConfigObject)       
            }
            
            If($EnableTargetedDomainsProtection -eq $True)
            {

                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="EnableTargetedDomainsProtection"
                $ConfigObject.ConfigData=$EnableTargetedDomainsProtection
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
    
            If($EnableOrganizationDomainsProtection -eq $True)
            {

                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="EnableOrganizationDomainsProtection"
                $ConfigObject.ConfigData=$EnableOrganizationDomainsProtection
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

            
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="TargetedDomainProtectionAction"
            $ConfigObject.ConfigData=$TargetedDomainProtectionAction
    
            If($TargetedDomainProtectionAction -eq "Quarantine")
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

            If($TargetedDomainProtectionAction -eq "Delete" -or $TargetedDomainProtectionAction -eq "Redirect")
            {
                # For either Delete or Quarantine we should raise an informational
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
                $ConfigObject.InfoText = "The $($TargetedDomainProtectionAction) option may impact the users ability to release emails and may impact user experience."
                   }
            }

            $this.AddConfig($ConfigObject)
    
        }
    
        If($PolicyExists -eq $False)
        {

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="All"
            $ConfigObject.ConfigItem="Enabled"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")  

            $this.AddConfig($ConfigObject)
     
        }

    }

}