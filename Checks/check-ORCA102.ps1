using module "..\ORCA.psm1"

class ORCA102 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA102()
    {
        $this.Control="ORCA-102"
        $this.Area="Anti-Spam Policies"
        $this.Name="Advanced Spam Filter (ASF)"
        $this.PassText="Advanced Spam filter options are turned off"
        $this.FailRecommendation="Turn off Advanced Spam filter (ASF) options in Anti-Spam filter policies"
        $this.Importance="Settings in the Advanced Spam Filter (ASF) are currently being deprecated. It is recommended to disable ASF settings."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
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
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {
            $IsPolicyDisabled = $false
            $IncreaseScoreWithImageLinks = $($Policy.IncreaseScoreWithImageLinks) 
            $IncreaseScoreWithNumericIps = $($Policy.IncreaseScoreWithNumericIps) 
            $IncreaseScoreWithRedirectToOtherPort = $($Policy.IncreaseScoreWithRedirectToOtherPort) 
            $IncreaseScoreWithBizOrInfoUrls = $($Policy.IncreaseScoreWithBizOrInfoUrls) 
            $MarkAsSpamEmptyMessages = $($Policy.MarkAsSpamEmptyMessages) 
            $MarkAsSpamJavaScriptInHtml = $($Policy.MarkAsSpamJavaScriptInHtml) 
            $MarkAsSpamFramesInHtml = $($Policy.MarkAsSpamFramesInHtml) 
            $MarkAsSpamObjectTagsInHtml = $($Policy.MarkAsSpamObjectTagsInHtml) 
            $MarkAsSpamEmbedTagsInHtml = $($Policy.MarkAsSpamEmbedTagsInHtml) 
            $MarkAsSpamFormTagsInHtml = $($Policy.MarkAsSpamFormTagsInHtml) 
            $MarkAsSpamWebBugsInHtml = $($Policy.MarkAsSpamWebBugsInHtml) 
            $MarkAsSpamSensitiveWordList = $($Policy.MarkAsSpamSensitiveWordList) 
            $MarkAsSpamFromAddressAuthFail = $($Policy.MarkAsSpamFromAddressAuthFail) 
            $MarkAsSpamNdrBackscatter = $($Policy.MarkAsSpamNdrBackscatter) 
            $MarkAsSpamSpfRecordHardFail = $($Policy.MarkAsSpamSpfRecordHardFail) 
           
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
                $IncreaseScoreWithImageLinks = "N/A"
                $IncreaseScoreWithNumericIps = "N/A"
                $IncreaseScoreWithRedirectToOtherPort = "N/A"
                $IncreaseScoreWithBizOrInfoUrls = "N/A"
                $MarkAsSpamEmptyMessages = "N/A"
                $MarkAsSpamJavaScriptInHtml = "N/A"
                $MarkAsSpamFramesInHtml = "N/A"
                $MarkAsSpamObjectTagsInHtml ="N/A"
                $MarkAsSpamEmbedTagsInHtml = "N/A"
                $MarkAsSpamFormTagsInHtml = "N/A"
                $MarkAsSpamWebBugsInHtml ="N/A"
                $MarkAsSpamSensitiveWordList = "N/A" 
                $MarkAsSpamFromAddressAuthFail ="N/A"
                $MarkAsSpamNdrBackscatter = "N/A"
                $MarkAsSpamSpfRecordHardFail ="N/A"
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
            # Determine if ASF options are off or not
            If($IncreaseScoreWithImageLinks -eq "On" -or $IncreaseScoreWithNumericIps -eq "On" -or $IncreaseScoreWithRedirectToOtherPort -eq "On" -or $IncreaseScoreWithBizOrInfoUrls -eq "On" -or $MarkAsSpamEmptyMessages -eq "On" -or $MarkAsSpamJavaScriptInHtml -eq "On" -or $MarkAsSpamFramesInHtml -eq "On" -or $MarkAsSpamObjectTagsInHtml -eq "On" -or $MarkAsSpamEmbedTagsInHtml -eq "On" -or $MarkAsSpamFormTagsInHtml -eq "On" -or $MarkAsSpamWebBugsInHtml -eq "On" -or $MarkAsSpamSensitiveWordList -eq "On" -or $MarkAsSpamFromAddressAuthFail -eq "On" -or $MarkAsSpamNdrBackscatter -eq "On" -or $MarkAsSpamSpfRecordHardFail -eq "On") {
                If($IncreaseScoreWithImageLinks -eq "On") {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="IncreaseScoreWithImageLinks"
                    $ConfigObject.ConfigData=$IncreaseScoreWithImageLinks
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
                If ($IncreaseScoreWithNumericIps -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="IncreaseScoreWithNumericIps"
                    $ConfigObject.ConfigData=$IncreaseScoreWithNumericIps
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
                If ($IncreaseScoreWithRedirectToOtherPort -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="IncreaseScoreWithRedirectToOtherPort"
                    $ConfigObject.ConfigData=$IncreaseScoreWithRedirectToOtherPort
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
                If ($IncreaseScoreWithBizOrInfoUrls -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="IncreaseScoreWithBizOrInfoUrls"
                    $ConfigObject.ConfigData=$IncreaseScoreWithBizOrInfoUrls
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
                If ($MarkAsSpamEmptyMessages -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamEmptyMessages"
                    $ConfigObject.ConfigData=$MarkAsSpamEmptyMessages
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
                If ($MarkAsSpamJavaScriptInHtml -eq "On") 
                {
                    
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamJavaScriptInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamJavaScriptInHtml
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
                If ($MarkAsSpamFramesInHtml -eq "On") {
                                        
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamFramesInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamFramesInHtml
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
                If ($MarkAsSpamObjectTagsInHtml -eq "On") 
                {
                                                            
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamObjectTagsInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamObjectTagsInHtml
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
                If ($MarkAsSpamEmbedTagsInHtml -eq "On") 
                {
                                                                                
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamEmbedTagsInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamEmbedTagsInHtml
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
                If ($MarkAsSpamFormTagsInHtml -eq "On") 
                {
                                                                                                    
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamFormTagsInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamFormTagsInHtml
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
                If ($MarkAsSpamWebBugsInHtml -eq "On") 
                {
                                                                                                                        
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamWebBugsInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamWebBugsInHtml
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
                If ($MarkAsSpamSensitiveWordList -eq "On") 
                {
                                                                                                                                      
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamSensitiveWordList"
                    $ConfigObject.ConfigData=$MarkAsSpamSensitiveWordList
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
                If ($MarkAsSpamFromAddressAuthFail -eq "On") 
                {
                                                                                                                                                          
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamFromAddressAuthFail"
                    $ConfigObject.ConfigData=$MarkAsSpamFromAddressAuthFail
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
                If ($MarkAsSpamNdrBackscatter -eq "On") 
                {
                                                                                                                                                                              
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamNdrBackscatter"
                    $ConfigObject.ConfigData=$MarkAsSpamNdrBackscatter
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
                If ($MarkAsSpamSpfRecordHardFail -eq "On") 
                {
                                                                                                                                                                             
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamSpfRecordHardFail"
                    $ConfigObject.ConfigData=$MarkAsSpamSpfRecordHardFail
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
    
            }
            else 
            {
                                                                                                                                                                        
                $ConfigObject = [ORCACheckConfig]::new()
                    
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="ASF Options"
                $ConfigObject.ConfigData="Disabled"
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
        }        

    }

}