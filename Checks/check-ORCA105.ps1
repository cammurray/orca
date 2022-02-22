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
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Safe links"="https://aka.ms/orca-atpp-action-safelinksv2"
            "Set up Office 365 ATP Safe Links policies"="https://aka.ms/orca-atpp-docs-10"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $Check = "ATP"
        $CountOfPolicies = ($Config["SafeLinksPolicy"] | Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in ($Config["SafeLinksPolicy"] | Where-Object {$_.IsEnabled -eq $True})) 
        {
            $IsPolicyEnabled = $true
            $IsBuiltIn = $false
            if($($Policy.Name) -ilike "Built-In" -and $CountOfPolicies -gt 1)
            {
                $IsBuiltIn =$True
            }
            <#
            
            DeliverMessageAfterScan
            
            #>

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="DeliverMessageAfterScan"
                $ConfigObject.ConfigData=$($Policy.DeliverMessageAfterScan)

                # Determine if DeliverMessageAfterScan is on for this safelinks policy
                If($Policy.DeliverMessageAfterScan -eq $true) 
                {                 
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                }
                Else 
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                }

                # Add config to check
                $this.AddConfig($ConfigObject)

            <#
            
            ScanUrls
            
            #>

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="ScanUrls"
                $ConfigObject.ConfigData=$($Policy.ScanUrls)

                If($Policy.ScanUrls -eq $true)
                {                 
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")                
                }
                Else 
                {                 
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                }

                

                # Add config to check
                $this.AddConfig($ConfigObject)

        }

        If(@($Config["SafeLinksPolicy"] | Where-Object {$_.IsEnabled -eq $True}).Count -eq 0)
        {

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="All"
            $ConfigObject.ConfigItem="Enabled"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }    

    }

}