using module "..\ORCA.psm1"

class ORCA140 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA140()
    {
        $this.Control=140
        $this.Area="Anti-Spam Policies"
        $this.Name="High Confidence Spam Action"
        $this.PassText="High Confidence Spam action set to Quarantine message"
        $this.FailRecommendation="Change High Confidence Spam action to Quarantine message"
        $this.Importance="It is recommended to configure High Confidence Spam detection action to Quarantine message."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Action"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }  
    }

    <#
    
        RESULTS
    
    #>
    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count  
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
            $IsPolicyDisabled = $false
            $HighConfidenceSpamAction = $($Policy.HighConfidenceSpamAction)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:HostedContentPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
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

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem=$policyname
            
            # Fail if HighConfidenceSpamAction is not set to Quarantine
    
            If($HighConfidenceSpamAction -eq "Quarantine") 
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.ConfigData="N/A"
    
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.ConfigData=$HighConfidenceSpamAction
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                    $ConfigObject.ConfigData=$HighConfidenceSpamAction
    
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                   }
            } 
            else 
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.ConfigData="N/A"    
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.ConfigData=$HighConfidenceSpamAction
    
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                    $ConfigObject.ConfigData=$HighConfidenceSpamAction
    
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                   }
            }

            # For either Delete or Quarantine we should raise an informational
            If($HighConfidenceSpamAction -eq "Delete" -or $HighConfidenceSpamAction -eq "Redirect")
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.ConfigData="N/A"    
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.ConfigData=$HighConfidenceSpamAction
    
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                $ConfigObject.ConfigData=$HighConfidenceSpamAction
    
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $(HighConfidenceSpamAction) option may impact the users ability to release emails and may impact user experience."
                   }
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }        

    }

}