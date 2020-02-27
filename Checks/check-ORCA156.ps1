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
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        If($Config["AtpPolicy"].TrackClicks -eq $False -and $($Config["AtpPolicy"].EnableSafeLinksForClients -eq $True -or $Config["AtpPolicy"].EnableSafeLinksForWebAccessCompanion -eq $True -or $Config["AtpPolicy"].EnableSafeLinksForO365Clients -eq $True))
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Fail"
                Object=$($Config["AtpPolicy"].Name)
                ConfigItem="TrackClicks"
                ConfigData=$($Config["AtpPolicy"].TrackClicks)
                Rule="TrackClicks off and EnableSafeLinksForClients or EnableSafeLinksForWebAccessCompanion or EnableSafeLinksForO365Clients enabled"
                Control=$this.Control
            }
        }
        ElseIf ($Config["AtpPolicy"].TrackClicks -eq $True)
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Pass"
                Object=$($Config["AtpPolicy"].Name)
                ConfigItem="TrackClicks"
                ConfigData=$($Config["AtpPolicy"].TrackClicks)
                Rule="TrackClicks in Office 365 Apps, Office for iOS and Android in ATP Policy"
                Control=$this.Control
            }            
        }

        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
            # Determine if ATP link tracking is on for this safelinks policy
            If($Policy.DoNotTrackUserClicks -eq $false) {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="DoNotTrackUserClicks"
                    ConfigData=$($Policy.DoNotTrackUserClicks)
                    Rule="SafeLinks URL Tracking Enabled"
                    Control=$this.Control
                }
            } 
            else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="DoNotTrackUserClicks"
                    ConfigData=$($Policy.DoNotTrackUserClicks)
                    Rule="SafeLinks URL Tracking Enabled"
                    Control=$this.Control
                }
            }
        }        

    }

}