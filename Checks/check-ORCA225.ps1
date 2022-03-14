<#

225 Checks to determine if ATP SafeDocs is enabled in the ATP configuration.

#>

using module "..\ORCA.psm1"

class ORCA225 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA225()
    {
        $this.Control=225
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Documents for Office clients"
        $this.PassText="Safe Documents is enabled for Office clients"
        $this.FailRecommendation="Enable Safe Documents for Office clients"
        $this.Importance="Safe Documents can assist protecting files opened in Office appplications. Before a user is allowed to trust a file opened in Office 365 ProPlus using Protected View, the file will be verified by Microsoft Defender Advanced Threat Protection."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Safe Attachments Policy"
        $this.ChiValue=[ORCACHI]::High
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Security & Compliance Center - Safe attachments"="https://aka.ms/orca-atpp-action-safeattachment"
            "Safe Documents in Microsoft 365 E5"="https://aka.ms/orca-atpp-docs-1"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$Config["AtpPolicy"].Name
        $ConfigObject.ConfigItem="EnableSafeDocs"
        $ConfigObject.ConfigData=$Config["AtpPolicy"].EnableSafeDocs
        # Determine if SafeDocs in ATP is enabled or not
        If($Config["AtpPolicy"].EnableSafeDocs -eq $false) 
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")   
        }
        Else
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")     
        }
        
        $this.AddConfig($ConfigObject)

    }

}