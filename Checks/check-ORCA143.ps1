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
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Name
            $ConfigObject.ConfigItem="InlineSafetyTipsEnabled"
            $ConfigObject.ConfigData=$($Policy.InlineSafetyTipsEnabled)

            # Fail if InlineSafetyTipsEnabled is not set to true
    
            If($Policy.InlineSafetyTipsEnabled -eq $true) 
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