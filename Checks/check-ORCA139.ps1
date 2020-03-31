using module "..\ORCA.psm1"

class ORCA139 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA139()
    {
        $this.Control=139
        $this.Area="Content Filter Policies"
        $this.Name="Spam Action"
        $this.Modes=@(
            @{
                Mode=[ORCAMode]::Standard
                PassText="Spam action set to move message to junk mail folder"
                FailRecommendation="Change Spam action to Move message to Junk Email Folder"
                Importance="It is recommended to configure Spam detection action to Move messages to Junk Email folder."
            },
            @{
                Mode=[ORCAMode]::Strict
                PassText="Spam action set to move message to quarantine"
                FailRecommendation="Change Spam action to Move message to Quarantine"
                Importance="It is recommended to configure Spam detection action to Move messages to Junk Email folder. For strict configuration, set the spam action to Quarantine."    
            }
        )
        $this.ExpandResults=$True
        $this.ItemName="Spam Policy"
        $this.DataType="Action"
        $this.Links= @{
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $Check = "Content Filter Actions"

        $this.Results = @()
    
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {

            # Check objects
            $StandardResult = New-Object -TypeName ORCACheckResult -Property @{
                Check=$Check
                ConfigItem=$($Policy.Name)
                ConfigData=$($Policy.SpamAction)
                Mode=[ORCAMode]::Standard
                Rule="SpamAction set to $($Policy.SpamAction)"
                Control=$this.Control
            }

            $StrictResult = New-Object -TypeName ORCACheckResult -Property @{
                Check=$Check
                ConfigItem=$($Policy.Name)
                ConfigData=$($Policy.SpamAction)
                Mode=[ORCAMode]::Strict
                Rule="SpamAction set to $($Policy.SpamAction)"
                Control=$this.Control
            }
    
            # For standard, this should be MoveToJmf
            If($Policy.SpamAction -ne "MoveToJmf") 
            {
                $StandardResult.Result="Fail"
            } 
            else 
            {
                $StandardResult.Result="Pass"
            }

            # For strict, this should be Quarantine
            If($Policy.SpamAction -ne "Quarantine") 
            {
                $StrictResult.Result="Fail"
            } 
            else 
            {
                $StrictResult.Result="Pass"
            }

            # Add the result objects
            $this.Results += $StandardResult
            $this.Results += $StrictResult
    
        }        

    }

}