using module "..\ORCA.psm1"

class ORCA102 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA102()
    {
        $this.Control="ORCA-102"
        $this.Area="Content Filter Policies"
        $this.Name="Advanced Spam Filter (ASF)"
        $this.PassText="Advanced Spam filter options are turned off"
        $this.FailRecommendation="Turn off Advanced Spam filter (ASF) options in Content filter policies"
        $this.Importance="Settings in the Advanced Spam Filter (ASF) are currently being deprecated. It is recommended to disable ASF settings."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {
            # Determine if ASF options are off or not
            If($Policy.IncreaseScoreWithImageLinks -eq "On" -or $Policy.IncreaseScoreWithNumericIps -eq "On" -or $Policy.IncreaseScoreWithRedirectToOtherPort -eq "On" -or $Policy.IncreaseScoreWithBizOrInfoUrls -eq "On" -or $Policy.MarkAsSpamEmptyMessages -eq "On" -or $Policy.MarkAsSpamJavaScriptInHtml -eq "On" -or $Policy.MarkAsSpamFramesInHtml -eq "On" -or $Policy.MarkAsSpamObjectTagsInHtml -eq "On" -or $Policy.MarkAsSpamEmbedTagsInHtml -eq "On" -or $Policy.MarkAsSpamFormTagsInHtml -eq "On" -or $Policy.MarkAsSpamWebBugsInHtml -eq "On" -or $Policy.MarkAsSpamSensitiveWordList -eq "On" -or $Policy.MarkAsSpamFromAddressAuthFail -eq "On" -or $Policy.MarkAsSpamNdrBackscatter -eq "On" -or $Policy.MarkAsSpamSpfRecordHardFail -eq "On") {
                If($Policy.IncreaseScoreWithImageLinks -eq "On") {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="IncreaseScoreWithImageLinks"
                    $ConfigObject.ConfigData=$($Policy.IncreaseScoreWithImageLinks)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.IncreaseScoreWithNumericIps -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="IncreaseScoreWithNumericIps"
                    $ConfigObject.ConfigData=$($Policy.IncreaseScoreWithNumericIps)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.IncreaseScoreWithRedirectToOtherPort -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="IncreaseScoreWithRedirectToOtherPort"
                    $ConfigObject.ConfigData=$($Policy.IncreaseScoreWithRedirectToOtherPort)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.IncreaseScoreWithBizOrInfoUrls -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="IncreaseScoreWithBizOrInfoUrls"
                    $ConfigObject.ConfigData=$($Policy.IncreaseScoreWithBizOrInfoUrls)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamEmptyMessages -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamEmptyMessages"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamEmptyMessages)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamJavaScriptInHtml -eq "On") 
                {
                    
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamJavaScriptInHtml"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamJavaScriptInHtml)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamFramesInHtml -eq "On") {
                                        
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamFramesInHtml"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamFramesInHtml)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamObjectTagsInHtml -eq "On") 
                {
                                                            
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamObjectTagsInHtml"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamObjectTagsInHtml)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamEmbedTagsInHtml -eq "On") 
                {
                                                                                
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamEmbedTagsInHtml"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamEmbedTagsInHtml)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamFormTagsInHtml -eq "On") 
                {
                                                                                                    
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamFormTagsInHtml"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamFormTagsInHtml)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamWebBugsInHtml -eq "On") 
                {
                                                                                                                        
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamWebBugsInHtml"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamWebBugsInHtml)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamSensitiveWordList -eq "On") 
                {
                                                                                                                                      
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamSensitiveWordList"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamSensitiveWordList)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamFromAddressAuthFail -eq "On") 
                {
                                                                                                                                                          
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamFromAddressAuthFail"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamFromAddressAuthFail)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamNdrBackscatter -eq "On") 
                {
                                                                                                                                                                              
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamNdrBackscatter"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamNdrBackscatter)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
                If ($Policy.MarkAsSpamSpfRecordHardFail -eq "On") 
                {
                                                                                                                                                                             
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$($Policy.Name)
                    $ConfigObject.ConfigItem="MarkAsSpamSpfRecordHardFail"
                    $ConfigObject.ConfigData=$($Policy.MarkAsSpamSpfRecordHardFail)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)

                }
    
            }
            else 
            {
                                                                                                                                                                        
                $ConfigObject = [ORCACheckConfig]::new()
                    
                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="ASF Options"
                $ConfigObject.ConfigData="Disabled"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)

            }
        }        

    }

}