using module "..\ORCA.psm1"

class ORCA100 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA100()
    {
        $this.Control = "ORCA-100"
        $this.Area = "Anti-Spam Policies"
        $this.Name="Bulk Complaint Level"
        $this.PassText="Bulk Complaint Level threshold is between 4 and 6"
        $this.FailRecommendation="Set the Bulk Complaint Level threshold to be 6"
            $this.Importance="Differentiation between bulk and spam can be subjective. BCL uses internal and external signals, including recipient complaint patterns and sender behavior, to classify bulk email. Lowering the threshold identifies more messages as bulk and can reduce unwanted bulk in user inboxes, but setting it too low can increase false positives and may be too restrictive."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Bulk Complaint Level Threshold"
        $this.Links= @{
            "Bulk Complaint Level values"="https://aka.ms/orca-antispam-docs-1"
            "Recommended settings for EOP and Microsoft Defender for Office 365 security"="https://aka.ms/orca-atpp-docs-6"
            "Microsoft 365 Defender Portal - Anti-spam settings"="https://security.microsoft.com/antispam"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            $BulkThreshold = $($Policy.BulkThreshold)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigData=$BulkThreshold
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Standard check - between 4 and 6
            If($BulkThreshold -ge 4 -and $BulkThreshold -le 6)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            }

            # Strict check - is 4
            If($BulkThreshold -eq 4)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Fail)
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
    
        }

    }

}