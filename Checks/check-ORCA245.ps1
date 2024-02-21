using module "..\ORCA.psm1"

class ORCA245 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA245()
    {
        $this.Control="ORCA-245"
        $this.Area="Anti-Spam Policies"
        $this.Name="Advanced Spam Filter (ASF) MarkAsSpamSpfRecordHardFail option"
        $this.PassText="Advanced Spam filter MarkAsSpamSpfRecordHardFail option is turned off"
        $this.FailRecommendation="Turn off Advanced Spam filter (ASF) MarkAsSpamSpfRecordHardFail option in Anti-Spam filter policies"
        $this.Importance="Settings in the Advanced Spam Filter (ASF) are known to cause false-positive detections .MarkAsSpamSpfRecordHardFail option is not recommended and will cause false positives. Failing SPF does not necessarily mean that a message is spoofed, such as in instances where DMARC/DKIM are deployed and aligning. Please validate your requirement to use MarkAsSpamSpfRecordHardFail."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            "Microsoft 365 Defender Portal - Anti-spam settings"="https://security.microsoft.com/antispam"
            "Recommended settings for EOP and Microsoft Defender for Office 365 security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {

            $IsPolicyDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            $MarkAsSpamSpfRecordHardFail = $($Policy.MarkAsSpamSpfRecordHardFail) 

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            If ($MarkAsSpamSpfRecordHardFail -eq "On") 
            {
                                                                                                                                                                         
                $ConfigObject = [ORCACheckConfig]::new()
                
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="MarkAsSpamSpfRecordHardFail"
                $ConfigObject.ConfigData=$MarkAsSpamSpfRecordHardFail
                $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                $ConfigObject.ConfigWontApply=$ConfigWontApply
                $ConfigObject.ConfigReadonly=$Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                $this.AddConfig($ConfigObject)

            } else {
                $ConfigObject = [ORCACheckConfig]::new()
                    
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="MarkAsSpamSpfRecordHardFail"
                $ConfigObject.ConfigData="Disabled"
                $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                $ConfigObject.ConfigWontApply=$ConfigWontApply
                $ConfigObject.ConfigReadonly=$Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)
            }

        }        

    }

}