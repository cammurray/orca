using module "..\ORCA.psm1"

class ORCA105 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA105()
    {
        $this.Control="ORCA-105"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Links Synchronous URL detonation"
        $this.PassText="Safe Links Synchronous URL detonation is enabled"
        $this.FailRecommendation="Enable Safe Links Synchronous URL detonation"
        $this.Importance="When the 'Wait for URL scanning to complete before delivering the message' option is configured, messages that contain URLs to be scanned will be held until the URLs finish scanning and are confirmed to be safe before the messages are delivered."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://aka.ms/orca-atpp-action-safelinksv2"
            "Set up Office 365 ATP Safe Links policies"="https://aka.ms/orca-atpp-docs-10"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $Check = "ATP"
        #$CountOfPolicies = ($Config["SafeLinksPolicy"] | Where-Object {$_.IsEnabled -eq $True}).Count
        $CountOfPolicies = ($global:SafeLinkPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in ($Config["SafeLinksPolicy"] )) 
        {
            $IsPolicyDisabled = $false
            $DeliverMessageAfterScan =$($Policy.DeliverMessageAfterScan)
            $ScanUrls = $($Policy.ScanUrls)

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
                $DeliverMessageAfterScan = "N/A"
                $ScanUrls = "N/A"
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

            <#
            
            DeliverMessageAfterScan
            
            #>

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object= $policyname
                $ConfigObject.ConfigItem="DeliverMessageAfterScan"
                $ConfigObject.ConfigData=$DeliverMessageAfterScan

                # Determine if DeliverMessageAfterScan is on for this safelinks policy
                If($DeliverMessageAfterScan -eq $true) 
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

            <#
            
            ScanUrls
            
            #>

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object= $policyname
                $ConfigObject.ConfigItem="ScanUrls"
                $ConfigObject.ConfigData=$ScanUrls

                If($ScanUrls -eq $true)
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

        If(@($Config["SafeLinksPolicy"] | Where-Object {$_.IsEnabled -eq $True}).Count -eq 0)
        {

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="All"
            $ConfigObject.ConfigItem="Enabled"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }    

    }

}

