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
        $this.Importance="Safe Attachments assists scanning for zero day malware by using behavioural analysis and sandboxing, supplimenting signature definitions."
        $this.CheckType = [CheckType]::ObjectPropertyValue
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        # Determine if ATP is enabled or not
        If($Config["AtpPolicy"].EnableATPForSPOTeamsODB -eq $true) 
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Pass"
                Object="Global Policy"
                ConfigItem="EnableATPForSPOTeamsODB"
                ConfigData=$Config["AtpPolicy"].EnableATPForSPOTeamsODB
                Control=$this.Control
            }
        } 
        else 
        {
            $this.Results += New-Object -TypeName psobject -Property @{
                Result="Fail"
                Object="Global Policy"
                ConfigItem="EnableATPForSPOTeamsODB"
                ConfigData=$Config["AtpPolicy"].EnableATPForSPOTeamsODB
                Control=$this.Control
            }
        }      

    }

}