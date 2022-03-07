<#

ORCA-117

Checks to determine if SafeLinks action for unknown potentially malicious URLs in messages is on.

#>

using module "..\ORCA.psm1"

class ORCA117 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA117()
    {
        $this.Control=117
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Action for unknown potentially malicious URLs in messages"
        $this.PassText="Safe Links policy action is enabled"
        $this.FailRecommendation="Enable Safe Links policy action for unknown potentially malicious URLs in messages"
        $this.Importance="When Safe Links policy action is eanbled URLs in messages will be rewritten and checked against a list of known malicious links when user clicks on the link."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Safe Links policy"
        $this.ChiValue=[ORCACHI]::Medium
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://aka.ms/orca-atpp-action-safelinksv2"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $Enabled = $False
        $CountOfPolicies = ($global:SafeLinkPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
            $IsPolicyDisabled = $false
            $IsEnabled = $($Policy.IsEnabled)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:SafeLinkPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
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

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="IsEnabled"
            

            # Determine if Safe Links policy action for unknown potentially malicious URLs in messages is enabled
            If($IsEnabled -eq $true) 
            {
                $Enabled = $True
                if($IsPolicyDisabled)
                {
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    $ConfigObject.ConfigData="N/A"
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    $ConfigObject.ConfigData=$IsEnabled
                }
                else
                   {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                    $ConfigObject.ConfigData=$IsEnabled
                   }
            } 
            Else 
            {
                if($IsPolicyDisabled)
                    {
                        $ConfigObject.ConfigData="N/A"
                        $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    elseif($IsBuiltIn)
                    {
                        $ConfigObject.ConfigData=$IsEnabled
                        $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    else
                       {
                        $ConfigObject.ConfigData=$IsEnabled
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                       }
            }

            $this.AddConfig($ConfigObject)
        }

        If($Enabled -eq $False)
        {

            # No policy enabling
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object ="All"
            $ConfigObject.ConfigItem="IsEnabled"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

            $this.AddConfig($ConfigObject)

        }    

    }

}