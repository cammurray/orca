using module "..\ORCA.psm1"

class ORCA223 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA223()
    {
        $this.Control=223
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="User Impersonation Action"
        $this.PassText="User impersonation action is set to move to Quarantine"
        $this.FailRecommendation="Configure user impersonation action to Quarantine"
        $this.Importance="User impersonation protection can detect spoofing of your sensitive users. Move messages that are caught using user impersonation detection to Quarantine."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Action"
        $this.Links= @{
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
    
        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}))
        {
    
            If($Policy.EnableTargetedUserProtection -eq $False)
            {
                # Policy Targeted UserProtection is off
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="EnableTargetedUserProtection"
                    ConfigData=$($Policy.EnableTargetedUserProtection)
                    Rule="Targeted User Protection Off"
                    Control=$this.Control
                }
            } 
            Else
            {
                # Check for action being MoveToJmf
                If($Policy.TargetedUserProtectionAction -eq "Quarantine")
                {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Pass"
                        Object=$($Policy.Name)
                        ConfigItem="TargetedUserProtectionAction"
                        ConfigData=$($Policy.TargetedUserProtectionAction)
                        Control=$this.Control
                    }   
                }
                Else
                {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Object=$($Policy.Name)
                        ConfigItem="TargetedUserProtectionAction"
                        ConfigData=$($Policy.TargetedUserProtectionAction)
                        Control=$this.Control
                    }                 
                }
            }
        }
    
        If($this.Results.Count -eq 0)
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Fail"
                Object="All"
                ConfigItem="Enabled"
                ConfigData="False"
                Control=$this.Control
            }            
        }    

    }

}