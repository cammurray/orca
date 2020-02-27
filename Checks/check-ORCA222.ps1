using module "..\ORCA.psm1"

class ORCA222 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA222()
    {
        $this.Control=222
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Domain Impersonation Action"
        $this.PassText="Domain Impersonation action is set to move to Quarantine"
        $this.FailRecommendation="Configure domain impersonation action to Quarantine"
        $this.Importance="Domain Impersonation can detect impersonation attempts against your domains or domains that look very similiar to your domains. Move messages that are caught using this impersonation protection to Quarantine."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
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
    
            If($Policy.EnableTargetedDomainsProtection -eq $False -and $Policy.EnableOrganizationDomainsProtection -eq $False)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="EnableTargetedDomainsProtection"
                    ConfigData=$($Policy.EnableTargetedDomainsProtection)
                    Control=$this.Control
                }
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="EnableOrganizationDomainsProtection"
                    ConfigData=$($Policy.EnableOrganizationDomainsProtection)
                    Control=$this.Control
                }           
            }
    
            If($Policy.EnableTargetedDomainsProtection -eq $True)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="EnableTargetedDomainsProtection"
                    ConfigData=$Policy.EnableTargetedDomainsProtection
                    Control=$this.Control
                }            
            }
    
            If($Policy.EnableOrganizationDomainsProtection -eq $True)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="EnableOrganizationDomainsProtection"
                    ConfigData=$Policy.EnableOrganizationDomainsProtection
                    Control=$this.Control
                }            
            }
    
            If($Policy.TargetedDomainProtectionAction -ne "Quarantine")
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="TargetedDomainProtectionAction"
                    ConfigData=$($Policy.TargetedDomainProtectionAction)
                    Control=$this.Control
                }
            }
            Else 
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="TargetedDomainProtectionAction"
                    ConfigData=$($Policy.TargetedDomainProtectionAction)
                    Control=$this.Control
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
                Rule="No Enabled AntiPhish Policy"
                Control=$this.Control
            }            
        }

    }

}