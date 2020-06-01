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
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://protection.office.com/antispam"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp?view=o365-worldwide#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
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