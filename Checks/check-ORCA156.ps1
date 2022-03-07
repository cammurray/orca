<#

156 Determines if SafeLinks URL tracing is enabled on the default policy for Office apps or in a Policy, does not however check that there is a rule enforcing this policy.

#>

using module "..\ORCA.psm1"

class ORCA156 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA156()
    {
        $this.Control=156
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Links Tracking"
        $this.PassText="Safe Links Policies are tracking when user clicks on safe links"
        $this.FailRecommendation="Enable tracking of user clicks in Safe Links Policies"
        $this.Importance="When these options are configured, click data for URLs in Word, Excel, PowerPoint, Visio documents and in emails is stored by Safe Links. This information can help dealing with phishing, suspicious email messages and URLs."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
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
        #$CountOfPolicies = ($Config["SafeLinksPolicy"]).Count + ($Config["AtpPolicy"]).Count
        $CountOfPolicies = ($global:SafeLinkPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count

        $IsBuiltIn0 = $false
        $policyname0 = $($Config["AtpPolicy"].Name)
        $configdata = $($Config["AtpPolicy"].TrackClicks)
        if($policyname0 -match "Built-In" -and $CountOfPolicies -gt 1)
        {
            $IsBuiltIn0 =$True
            $policyname0 = "$policyname0" +" [Built-In]"
        }
        elseif(($policyname0 -eq "Default" -or $policyname0 -eq "Office365 AntiPhish Default") -and $CountOfPolicies -gt 1)
        {
            $IsBuiltIn0 =$True
            $policyname0 = "$policyname0" +" [Default]"
        }

        # Global ATP Policy
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$policyname0
        $ConfigObject.ConfigItem="TrackClicks"
        $ConfigObject.ConfigData=$configdata

        If($Config["AtpPolicy"].TrackClicks -eq $False -and $($Config["AtpPolicy"].EnableSafeLinksForClients -eq $True -or $Config["AtpPolicy"].EnableSafeLinksForWebAccessCompanion -eq $True -or $Config["AtpPolicy"].EnableSafeLinksForO365Clients -eq $True))
        {
            if($IsBuiltIn0)
            {
                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
            }
            else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")   
            }  
        }
        ElseIf ($Config["AtpPolicy"].TrackClicks -eq $True)
        {
            if($IsBuiltIn0)
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

       
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
            $IsPolicyDisabled = $false
            $DoNotTrackUserClicks = $($Policy.DoNotTrackUserClicks)

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
                $DoNotTrackUserClicks = "N/A"
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
            $ConfigObject.ConfigItem="DoNotTrackUserClicks"
            $ConfigObject.ConfigData=$DoNotTrackUserClicks

            # Determine if ATP link tracking is on for this safelinks policy
            If($DoNotTrackUserClicks -eq $false)
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
            else 
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