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
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $PolicyExists = $False

        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}))
        {

            $PolicyExists = $True

            <#
            
            EnableTargetedDomainsProtection / EnableOrgainizationDomainsProtection
            
            #>

            If($Policy.EnableTargetedDomainsProtection -eq $False -and $Policy.EnableOrganizationDomainsProtection -eq $False)
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()

                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="EnableTargetedDomainsProtection"
                $ConfigObject.ConfigData=$Policy.EnableTargetedDomainsProtection
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                $this.AddConfig($ConfigObject)
                
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()

                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="EnableOrganizationDomainsProtection"
                $ConfigObject.ConfigData=$Policy.EnableOrganizationDomainsProtection
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                
                $this.AddConfig($ConfigObject)       
            }
            
            If($Policy.EnableTargetedDomainsProtection -eq $True)
            {

                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="EnableTargetedDomainsProtection"
                $ConfigObject.ConfigData=$Policy.EnableTargetedDomainsProtection
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)

            }
    
            If($Policy.EnableOrganizationDomainsProtection -eq $True)
            {

                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$($Policy.Name)
                $ConfigObject.ConfigItem="EnableOrganizationDomainsProtection"
                $ConfigObject.ConfigData=$Policy.EnableOrganizationDomainsProtection
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)
         
            }

            
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="TargetedDomainProtectionAction"
            $ConfigObject.ConfigData=$Policy.TargetedDomainProtectionAction
    
            If($Policy.TargetedDomainProtectionAction -eq "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")            
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")  
            }

            If($Policy.TargetedDomainProtectionAction -eq "Delete" -or $Policy.TargetedDomainProtectionAction -eq "Redirect")
            {
                # For either Delete or Quarantine we should raise an informational
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($Policy.TargetedDomainProtectionAction) option may impact the users ability to release emails and may impact user experience."
            }

            $this.AddConfig($ConfigObject)
    
        }
    
        If($PolicyExists -eq $False)
        {

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="All"
            $ConfigObject.ConfigItem="Enabled"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")  

            $this.AddConfig($ConfigObject)
     
        }

    }

}