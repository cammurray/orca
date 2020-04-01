using module "..\ORCA.psm1"

class ORCA100 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA100()
    {
        $this.Control = "ORCA-100"
        $this.Area = "Content Filter Policies"
        $this.Name="Bulk Complaint Level"
        $this.Modes=@(
            @{
                Mode=[ORCAMode]::Standard
                PassText="Bulk Complaint Level threshold is between 4 and 6"
                FailRecommendation="Set the Bulk Complaint Level threshold to be between 4 and 6"
                Importance="The differentiation between bulk and spam can sometimes be subjective. The bulk complaint level is based on the number of complaints from the sender. Decreasing the threshold can decrease the amount of perceived spam received, however, too low may be considered too strict."
            },
            @{
                Mode=[ORCAMode]::Strict
                PassText="Spam action set to move message to quarantine"
                FailRecommendation="Set the Bulk Complaint Level threshold to 4"
                Importance="The differentiation between bulk and spam can sometimes be subjective. The bulk complaint level is based on the number of complaints from the sender. Decreasing the threshold can decrease the amount of perceived spam received, however, too low may be considered too strict. In strict configuration, we recommend setting this to 4."   
            }
        )
        $this.ExpandResults=$True
        $this.ItemName="Content Filter Policy"
        $this.DataType="Bulk Complaint Level Threshold"
        $this.Links= @{
            "Bulk Complaint Level values"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/bulk-complaint-level-values"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {

            # Check objects
            $StandardResult = New-Object -TypeName ORCACheckResult -Property @{
                ConfigItem=$($Policy.Name)
                ConfigData=$Policy.BulkThreshold
                Mode=[ORCAMode]::Standard
                Control=$this.Control
            }

            $StrictResult = New-Object -TypeName ORCACheckResult -Property @{
                ConfigItem=$($Policy.Name)
                ConfigData=$Policy.BulkThreshold
                Mode=[ORCAMode]::Strict
                Control=$this.Control
            }
    
            # Standard check - between 4 and 6
            If($Policy.BulkThreshold -ge 4 -and $Policy.BulkThreshold -le 6)
            {
                $StandardResult.Result = "Pass"        
            }
            Else 
            {
                $StandardResult.Result = "Fail"                      
            }

            # Strict check - is 4
            If($Policy.BulkThreshold -eq 4)
            {
                $StrictResult.Result = "Pass"        
            }
            Else 
            {
                $StrictResult.Result = "Fail"                      
            }

            # Add standard and strict results
            $this.Results += $StandardResult
            $this.Results += $StrictResult
    
        }

    }

}