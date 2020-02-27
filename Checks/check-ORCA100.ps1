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
        $this.PassText="Bulk Complaint Level threshold is between 4 and 6"
        $this.FailRecommendation="Set the Bulk Complaint Level threshold to be between 4 and 6"
        $this.Importance="The differentiation between bulk and spam can sometimes be subjective. The bulk complaint level is based on the number of complaints from the sender. Decreasing the threshold can decrease the amount of perceived spam received, however, too low may be considered too strict."
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
    
            If($Policy.BulkThreshold -ge 4 -and $Policy.BulkThreshold -le 6)
            {
                $this.Results += New-Object -TypeName ORCACheckResult -Property @{
                    Result="Pass"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$Policy.BulkThreshold
                    Control=$this.Control
                }                
            }
            Else 
            {
                $this.Results += New-Object -TypeName ORCACheckResult -Property @{
                    Result="Fail"
                    ConfigItem=$($Policy.Name)
                    ConfigData=$Policy.BulkThreshold
                    Control=$this.Control
                }                            
            }
    
        }

    }

}