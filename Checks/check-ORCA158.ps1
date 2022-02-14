<#

158 Checks to determine if ATP is enabled for SharePoint, Teams, and OD4B as per 'tickbox' in the ATP configuration.

#>

using module "..\ORCA.psm1"

class ORCA158 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA158()
    {
        $this.Control=158
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Attachments SharePoint and Teams"
        $this.PassText="Safe Attachments is enabled for SharePoint and Teams"
        $this.FailRecommendation="Enable Safe Attachments for SharePoint and Teams"
        $this.Importance="Safe Attachments can assist by scanning for zero day malware by using behavioural analysis and sandboxing techniques. These checks suppliment signature definitions."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Safe Attachments Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Security & Compliance Center - Safe attachments"="https://aka.ms/orca-atpp-action-safeattachment"
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
        $ConfigObject.ConfigItem="EnableATPForSPOTeamsODB"
        $ConfigObject.ConfigData=$Config["AtpPolicy"].EnableATPForSPOTeamsODB
        # Determine if ATP is enabled or not
        If($Config["AtpPolicy"].EnableATPForSPOTeamsODB -eq $false) 
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