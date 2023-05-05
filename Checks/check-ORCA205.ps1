<#

205 Checks to determine if Common attachment type filter is enbaled in EOP Anti-malware policy.

#>

using module "..\ORCA.psm1"

class ORCA205 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA205()
    {
        $this.Control=205
        $this.Area="Malware Filter Policy"
        $this.Name="Common Attachment Type Filter"
        $this.PassText="Common attachment type filter is enabled"
        $this.FailRecommendation="Enable common attachment type filter"
        $this.Importance="The common attachment type filter can block file types that commonly contain malware, including in internal emails."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            "Security & Compliance Center - Anti-malware"="https://aka.ms/orca-mfp-action-antimalware"
            "Configure anti-malware policies"="https://aka.ms/orca-mfp-docs-1"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["MalwareFilterPolicy"]).Count
        $CountOfPolicies = ($global:MalwarePolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
      
        ForEach($Policy in $Config["MalwareFilterPolicy"])
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableFileFilter = $($Policy.EnableFileFilter)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)
            $FileTypesCount =$(@($Policy.FileTypes).Count)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableFileFilter"
            $ConfigObject.ConfigData=$($EnableFileFilter)
            $ConfigObject.ConfigDisabled = $IsPolicyDisabled
            $ConfigObject.ConfigReadonly = $Policy.IsPreset

            # Fail if EnableFileFilter is not set to true or FileTypes is empty in the policy

            If($EnableFileFilter -eq $false) 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            $this.AddConfig($ConfigObject)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="FileTypes"
            $ConfigObject.ConfigDisabled = $IsPolicyDisabled
            $ConfigObject.ConfigReadonly = $Policy.IsPreset

            If($FileTypesCount.Count -eq 0) 
            {
                $ConfigObject.ConfigData=$FileTypesCount
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            Else
            {
                $ConfigObject.ConfigData=$FileTypesCount
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            $this.AddConfig($ConfigObject) 
            
        }
        
    }

}