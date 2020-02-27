using module "..\ORCA.psm1"

class ORCA143 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA143()
    {
        $this.Control=143
        $this.Area="Content Filter Policies"
        $this.Name="Safety Tips"
        $this.PassText="Safety Tips are enabled"
        $this.FailRecommendation="Safety Tips should be enabled"
        $this.Importance="By default, safety tips can provide useful security information when reading an email."
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {

            # Fail if InlineSafetyTipsEnabled is not set to true
    
            If($Policy.InlineSafetyTipsEnabled -eq $false) 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.InlineSafetyTipsEnabled)
                    Rule="InlineSafetyTipsEnabled is false - Safety Tips Disabled"
                    Control=$this.Control
                } 
            } 
            else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$($Policy.InlineSafetyTipsEnabled)
                    Rule="InlineSafetyTipsEnabled is true - Safety Tips Enabled"
                    Control=$this.Control
                } 
            }
        }        

    }

}