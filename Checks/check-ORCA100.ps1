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
        $this.Importance="The differentiation between bulk and spam can sometimes be subjective. The bulk complaint level is based on the number of complaints from the sender. Decreasing the threshold can decrease the amount of perceived spam received, however, too low may be considered too strict."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Bulk Complaint Level Threshold"
        $this.Links= @{
            "Bulk Complaint Level values"="https://aka.ms/orca-antispam-docs-1"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $BulkThreshold = $($Policy.BulkThreshold)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$($Policy.Name)
            $ConfigObject.ConfigData=$BulkThreshold
            $ConfigObject.ConfigDisabled = $IsPolicyDisabled
            $ConfigObject.ConfigReadonly = $Policy.IsPreset

            # Standard check - between 4 and 6
            If($BulkThreshold -ge 4 -and $BulkThreshold -le 6)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            # Strict check - is 4
            If($BulkThreshold -eq 4)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
    
        }

    }

}