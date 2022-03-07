using module "..\ORCA.psm1"

class ORCA139 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA139()
    {
        $this.Control=139
        $this.Area="Anti-Spam Policies"
        $this.Name="Spam Action"
        $this.PassText="Spam action set to move message to junk mail folder or quarantine"
        $this.FailRecommendation="Change Spam action to move message to Junk Email Folder"
        $this.Importance="It is recommended to configure Spam detection action to Move messages to Junk Email folder."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Action"
        $this.ChiValue=[ORCACHI]::Low
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
            $SpamAction = $($Policy.SpamAction)

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
                $SpamAction = "N/A"
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
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$($SpamAction)

            # For standard, this should be MoveToJmf
            If($SpamAction -ne "MoveToJmf") 
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
            else 
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
            If($SpamAction -ne "Quarantine") 
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
            else 
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

            # For either Delete or Redirect we should raise an informational
            If($SpamAction -eq "Delete" -or $SpamAction -eq "Redirect")
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
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($SpamAction) option may impact the users ability to release emails and may impact user experience."
                   }
            }
            
            $this.AddConfig($ConfigObject)
            
        }        

    }

}