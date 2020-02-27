using module "..\ORCA.psm1"

class ORCA105 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA105()
    {
        $this.Control="ORCA-105"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Links Synchronous URL detonation"
        $this.PassText="Safe Links Synchronous URL detonation is enabled"
        $this.FailRecommendation="Enable Safe Links Synchronous URL detonation"
        $this.Importance="When the 'Wait for URL scanning to complete before delivering the message' option is configured, messages that contain URLs to be scanned will be held until the URLs finish scanning and are confirmed to be safe before the messages are delivered."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Set up Office 365 ATP Safe Links policies"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-atp-safe-links-policies#step-4-learn-about-atp-safe-links-policy-options"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $Check = "ATP"
        
        ForEach($Policy in ($Config["SafeLinksPolicy"] | Where-Object {$_.IsEnabled -eq $True})) 
        {
            # Determine if DeliverMessageAfterScan is on for this safelinks policy
            If($Policy.DeliverMessageAfterScan -eq $true) 
            {
                $DeliverMessageAfterScan_Result = "Pass"
            }
            Else
            {
                $DeliverMessageAfterScan_Result = "Fail"
            }

            If($Policy.ScanUrls -eq $true)
            {
                $ScanURLs_Result = "Pass"
            }
            Else 
            {
                $ScanURLs_Result = "Fail"
            }

            $this.Results += New-Object -TypeName psobject -Property @{
                Result=$DeliverMessageAfterScan_Result
                Check=$Check
                Object=$($Policy.Name)
                ConfigItem="DeliverMessageAfterScan"
                ConfigData="$($Policy.DeliverMessageAfterScan)"
                Control=$this.Control
            }

            $this.Results += New-Object -TypeName psobject -Property @{
                Result=$ScanURLs_Result
                Check=$Check
                Object=$($Policy.Name)
                ConfigItem="ScanUrls"
                ConfigData="$($Policy.ScanUrls)"
                Control=$this.Control
            }    
        }

        If($this.Results.Count -eq 0)
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Fail"
                Check=$Check
                Object="All"
                ConfigItem="Enabled"
                ConfigData="False"
                Control=$this.Control
            } 
        }    

    }

}