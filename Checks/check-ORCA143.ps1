using module "..\ORCA.psm1"

class ORCA143 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA143()
    {
        $this.Control=143
        $this.Area="Anti-Spam Policies"
        $this.Name="Safety Tips"
        $this.PassText="Safety Tips are enabled"
        $this.FailRecommendation="Safety Tips should be enabled"
        $this.Importance="By default, safety tips can provide useful security information when reading an email."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Anti-Spam Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-antispam-docs-8"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $this.SkipInReport=$True
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count 
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $InlineSafetyTipsEnabled = $($Policy.InlineSafetyTipsEnabled)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)


            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="InlineSafetyTipsEnabled"
            $ConfigObject.ConfigData=$InlineSafetyTipsEnabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled

            # Fail if InlineSafetyTipsEnabled is not set to true
    
            If($InlineSafetyTipsEnabled -eq $true) 
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