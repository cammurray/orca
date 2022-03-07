<#

205 Checks to determine if Common attachment type filter is enbaled in EOP Anti-malware policy.

#>

using module "..\ORCA.psm1"

class ORCA205 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA205()
    {
        $this.Control=205
        $this.Area="Malware Filter Policy"
        $this.Name="Common Attachment Type Filter"
        $this.PassText="Common attachment type filter is enabled"
        $this.FailRecommendation="Enable common attachment type filter"
        $this.Importance="The common attachment type filter can block file types that commonly contain malware, including in internal emails."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            "Security & Compliance Center - Anti-malware"="https://aka.ms/orca-mfp-action-antimalware"
            "Configure anti-malware policies"="https://aka.ms/orca-mfp-docs-1"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["MalwareFilterPolicy"]).Count
        $CountOfPolicies = ($global:MalwarePolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
      
        ForEach($Policy in $Config["MalwareFilterPolicy"])
        {
            $IsPolicyDisabled = $false
            $EnableFileFilter = $($Policy.EnableFileFilter)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)
            $FileTypesCount =$(@($Policy.FileTypes).Count)
            ForEach($data in ($global:MalwarePolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" +" [Disabled]"
                $EnableFileFilter = "N/A"
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
            $ConfigObject.ConfigItem="EnableFileFilter"
            $ConfigObject.ConfigData=$($EnableFileFilter)

            # Fail if EnableFileFilter is not set to true or FileTypes is empty in the policy

            If($EnableFileFilter -eq $false) 
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

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="FileTypes"
           

            If($FileTypesCount.Count -eq 0) 
            {
                if($IsPolicyDisabled)
                    {
                        $ConfigObject.ConfigData="N/A"
                        $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    elseif($IsBuiltIn)
                    {
                        $ConfigObject.ConfigData=$FileTypesCount
                        $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    else
                       {
                        $ConfigObject.ConfigData=$FileTypesCount
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                       }
            }
            Else
            {
                if($IsPolicyDisabled)
                    {
                        $ConfigObject.ConfigData="N/A"
                        $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    elseif($IsBuiltIn)
                    {
                        $ConfigObject.ConfigData=$FileTypesCount
                        $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    else
                       {
                        $ConfigObject.ConfigData=$FileTypesCount
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                       }
            }

            $this.AddConfig($ConfigObject) 
            
        }
        
    }

}