using module "..\ORCA.psm1"

class ORCA113 : ORCACheck
{
    <#
    
        Check if AllowClickThrough is disabled in the organisation wide SafeLinks policy and if DoNotAllowClickThrough is True in SafeLink policies
    
    #>

    ORCA113()
    {
        $this.Control="ORCA-113"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Do not let users click through safe links"
        $this.PassText="DoNotAllowClickThrough is enabled in Safe Links policies"
        $this.FailRecommendation="Do not let users click through safe links to original URL"
        $this.Importance="Office 365 ATP Safe Links can help protect your organization by providing time-of-click verification of  web addresses (URLs) in email messages and Office documents. It is possible to allow users click through Safe Links to the original URL. It is recommended to configure Safe Links policies to not let users click through safe links."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://aka.ms/orca-atpp-action-safelinksv2"
            "Office 365 ATP Safe Links policies"="https://aka.ms/orca-atpp-docs-11"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-8"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        #$CountOfPolicies = ($Config["SafeLinksPolicy"]).Count
        $CountOfPolicies = ($global:SafeLinkPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count

        $IsBuiltIn0 = $false
        $policyname0 = $($Config["AtpPolicy"].Name)
        $configdata =$($Config["AtpPolicy"].AllowClickThrough)
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
        # Check objects
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object= $policyname0
        $ConfigObject.ConfigItem="AllowClickThrough"
        $ConfigObject.ConfigData= $configdata 

        If( $configdata -eq $True)
        {
            # Determine if AllowClickThrough is enabled in the policy applies to the entire organization
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
        Else
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
 
        # Add config to check
        $this.AddConfig($ConfigObject)
        
       
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {    
            $IsPolicyDisabled = $false
            $DoNotAllowClickThrough = $($Policy.DoNotAllowClickThrough)

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
                $DoNotAllowClickThrough = "N/A"
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
            $ConfigObject.Object=$policyName
            $ConfigObject.ConfigItem="DoNotAllowClickThrough"
            $ConfigObject.ConfigData=$DoNotAllowClickThrough

            # Determine if DoNotAllowClickThrough is True in safelinks policies
            If($Policy.DoNotAllowClickThrough -eq $true)
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

            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }

    }

}