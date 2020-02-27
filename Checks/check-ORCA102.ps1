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
        $this.PassText="Advanced Spam filter options are runed off"
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
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="IncreaseScoreWithImageLinks"
                        ConfigData=$($Policy.IncreaseScoreWithImageLinks)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.IncreaseScoreWithNumericIps -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="IncreaseScoreWithNumericIps"
                        ConfigData=$($Policy.IncreaseScoreWithNumericIps)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.IncreaseScoreWithRedirectToOtherPort -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="IncreaseScoreWithRedirectToOtherPort"
                        ConfigData=$($Policy.IncreaseScoreWithRedirectToOtherPort)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.IncreaseScoreWithBizOrInfoUrls -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="IncreaseScoreWithBizOrInfoUrls"
                        ConfigData=$($Policy.IncreaseScoreWithBizOrInfoUrls)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamEmptyMessages -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamEmptyMessages"
                        ConfigData=$($Policy.MarkAsSpamEmptyMessages)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamJavaScriptInHtml -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamJavaScriptInHtml"
                        ConfigData=$($Policy.MarkAsSpamJavaScriptInHtml)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamFramesInHtml -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamFramesInHtml"
                        ConfigData=$($Policy.MarkAsSpamFramesInHtml)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamObjectTagsInHtml -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamObjectTagsInHtml"
                        ConfigData=$($Policy.MarkAsSpamObjectTagsInHtml)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamEmbedTagsInHtml -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamEmbedTagsInHtml"
                        ConfigData=$($Policy.MarkAsSpamEmbedTagsInHtml)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamFormTagsInHtml -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamFormTagsInHtml"
                        ConfigData=$($Policy.MarkAsSpamFormTagsInHtml)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamWebBugsInHtml -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamWebBugsInHtml"
                        ConfigData=$($Policy.MarkAsSpamWebBugsInHtml)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamSensitiveWordList -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamSensitiveWordList"
                        ConfigData=$($Policy.MarkAsSpamSensitiveWordList)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamFromAddressAuthFail -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamFromAddressAuthFail"
                        ConfigData=$($Policy.MarkAsSpamFromAddressAuthFail)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamNdrBackscatter -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamNdrBackscatter"
                        ConfigData=$($Policy.MarkAsSpamNdrBackscatter)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
                If ($Policy.MarkAsSpamSpfRecordHardFail -eq "On") {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="MarkAsSpamSpfRecordHardFail"
                        ConfigData=$($Policy.MarkAsSpamSpfRecordHardFail)
                        Rule="Content Fileter policy ASF options"
                        Control=$this.Control
                    }
                }
    
            }
            else {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="ASF Options"
                    ConfigData="Disabled"
                    Rule="Content Fileter policy ASF options"
                    Control=$this.Control
                }
            }
        }        

    }

}