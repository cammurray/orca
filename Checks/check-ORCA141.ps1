using module "..\ORCA.psm1"

class ORCA141 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA141()
    {
        $this.Control=141
        $this.Area="Anti-Spam Policies"
        $this.Name="Bulk Action"
        $this.PassText="Bulk action set to Move message to Junk Email Folder"
        $this.FailRecommendation="Change bulk action to move messages to junk mail folder"
        $this.Importance="It is recommended to configure Bulk detection action to Move messages to Junk Email folder."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Action"
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
            $BulkSpamAction = $($Policy.BulkSpamAction)

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
                $BulkSpamAction = "N/A"
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
            

            # For standard Fail if BulkSpamAction is not set to MoveToJmf
    
            If($BulkSpamAction -ne "MoveToJmf") 
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.ConfigData="N/A"
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.ConfigData=$($BulkSpamAction)
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                    $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                   }
            } 
            else 
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.ConfigData="N/A"
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.ConfigData=$($BulkSpamAction)
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                    $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                   }
            }

            # For strict Fail if BulkSpamAction is not set to Quarantine

            If($BulkSpamAction -ne "Quarantine") 
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.ConfigData="N/A"
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.ConfigData=$($BulkSpamAction)
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                    $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
                   }
            } 
            else 
            {
                if($IsPolicyDisabled)
                {
                    $ConfigObject.ConfigData="N/A"
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.ConfigData=$($BulkSpamAction)
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                    $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
                   }
            }

            # For either Delete or Quarantine we should raise an informational

            If($BulkSpamAction -eq "Delete" -or $BulkSpamAction -eq "Redirect")
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($BulkSpamAction) option may impact the users ability to release emails and may impact user experience."
            }
            
            $this.AddConfig($ConfigObject)

        }        

    }

}