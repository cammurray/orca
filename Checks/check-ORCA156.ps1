<#

156 Determines if SafeLinks URL tracing is enabled on the default policy for Office apps or in a Policy, does not however check that there is a rule enforcing this policy.

#>

using module "..\ORCA.psm1"

class ORCA156 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA156()
    {
        $this.Control=156
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Links Tracking"
        $this.PassText="Safe Links Policies are tracking when user clicks on safe links"
        $this.FailRecommendation="Enable tracking of user clicks in Safe Links Policies"
        $this.Importance="When these options are configured, click data for URLs in Word, Excel, PowerPoint, Visio documents and in emails is stored by Safe Links. This information can help dealing with phishing, suspicious email messages and URLs."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://aka.ms/orca-atpp-action-safelinksv2"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        # Global ATP Policy
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$($Config["AtpPolicy"].Name)
        $ConfigObject.ConfigItem="TrackClicks"
        $ConfigObject.ConfigData=$($Config["AtpPolicy"].TrackClicks)

        If($Config["AtpPolicy"].TrackClicks -eq $False -and $($Config["AtpPolicy"].EnableSafeLinksForClients -eq $True -or $Config["AtpPolicy"].EnableSafeLinksForWebAccessCompanion -eq $True -or $Config["AtpPolicy"].EnableSafeLinksForO365Clients -eq $True))
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }
        ElseIf ($Config["AtpPolicy"].TrackClicks -eq $True)
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")     
        }

        $this.AddConfig($ConfigObject)

        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="DoNotTrackUserClicks"
            $ConfigObject.ConfigData=$($Policy.DoNotTrackUserClicks)

            # Determine if ATP link tracking is on for this safelinks policy
            If($Policy.DoNotTrackUserClicks -eq $false)
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