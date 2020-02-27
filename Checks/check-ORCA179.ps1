<#

179

Checks to determine if SafeLinks is re-wring internal to internal emails. Does not however,
check to determine if there is a rule enforcing this.

#>

using module "..\ORCA.psm1"

class ORCA179 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA179()
    {
        $this.Control=179
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Intra-organization Safe Links"
        $this.PassText="Safe Links is enabled intra-organization"
        $this.FailRecommendation="Enable Safe Links between internal users"
        $this.Importance="Phishing attacks are not limited from external users. Commonly, when one user is compromised, that user can be used in a process of lateral movement between different accounts in your organization. Configuring Safe Links so that internal messages are also re-written can assist with lateral movement using phishing."
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
            # Determine if ATP link tracking is on for this safelinks policy
            If($Policy.EnableForInternalSenders -eq $true) 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$Policy.EnableForInternalSenders
                    Rule="SafeLinks Enabled for Internal Senders"
                    Control=$this.Control
                }
            } 
            Else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$Policy.EnableForInternalSenders
                    Rule="SafeLinks Disabled for Internal Senders"
                    Control=$this.Control
                }
            }
        }

        If($this.Results.Count -eq 0)
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Fail"
                ConfigItem="All"
                ConfigData="Enabled False"
                Control=$this.Control
            }
        }    

    }

}