using module "..\ORCA.psm1"

class ORCA120_phish : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA120_phish()
    {
        $this.Control="120-phish"
        $this.Area="Zero Hour Autopurge"
        $this.Name="Zero Hour Autopurge Enabled for Phish"
        $this.PassText="Zero Hour Autopurge is Enabled"
        $this.FailRecommendation="Enable Zero Hour Autopurge"
        $this.Importance="Zero Hour Autopurge can assist removing false-negatives post detection from mailboxes. By default, it is enabled."
        $this.ExpandResults=$True
        $this.ItemName="Policy"
        $this.DataType="ZapEnabled Setting"
        $this.ChiValue=[ORCACHI]::VeryHigh
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Zero-hour auto purge - protection against spam and malware"="https://aka.ms/orca-zha-docs-2"
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
       
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
            $IsPolicyDisabled = $false
            $PhishZapEnabled = $($Policy.PhishZapEnabled)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:HostedContentPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$PhishZapEnabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled

            if($PhishZapEnabled -eq $true) 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

        }        

    }

}