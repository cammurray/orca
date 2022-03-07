using module "..\ORCA.psm1"

class ORCA104 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA104()
    {
        $this.Control="ORCA-104"
        $this.Area="Anti-Spam Policies"
        $this.Name="High Confidence Phish Action"
        $this.PassText="High Confidence Phish action set to Quarantine message"
        $this.FailRecommendation="Change High Confidence Phish action to Quarantine message"
        $this.Importance="It is recommended to configure the High Confidence Phish detection action to Quarantine so that these emails are not visible to the end user from within Outlook. As Phishing emails are designed to look legitimate, users may mistakenly think that a phishing email in Junk is false-positive."
        $this.ExpandResults=$True
        $this.ItemName="Spam Policy"
        $this.DataType="Action"
        $this.ChiValue=[ORCACHI]::High
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
        # Fail if HighConfidencePhishAction is not set to Quarantine

        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
            $IsPolicyDisabled = $false
            $HighConfidencePhishAction = $($Policy.HighConfidencePhishAction)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:HostedContentPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" + " [Disabled]"
                $HighConfidencePhishAction = "N/A"
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
            $ConfigObject.ConfigData=$HighConfidencePhishAction
    
            If($HighConfidencePhishAction -eq "Quarantine") 
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

            If($HighConfidencePhishAction -eq "Redirect" -or $HighConfidencePhishAction -eq "Delete")
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
                    $ConfigObject.InfoText = "The $($HighConfidencePhishAction) option may impact the users ability to release emails and may impact user experience. Consider using the Quarantine option for High Confidence Phish."
                }
            }
            # Add config to check
            $this.AddConfig($ConfigObject)

        }        

    }

}