<#

ORCA-228 - Check ATP Anti-Phishing trusted senders  

#>

using module "..\ORCA.psm1"

class ORCA228 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA228()
    {
        $this.Control=228
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Anti-phishing trusted senders"
        $this.PassText="No trusted senders in Anti-phishing policy"
        $this.FailRecommendation="Remove whitelisting on senders in Anti-phishing policy"
        $this.Importance="Adding senders as trusted in Anti-phishing policy will result in the action for protected domains, Protected users or mailbox intelligence protection will be not applied to messages coming from these senders. If a trusted sender needs to be added based on organizational requirements it should be reviewed regularly and updated as needed."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://protection.office.com/antiphishing"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
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

            #  Determine if tips for user impersonation is on

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="ExcludedSenders"
            $ConfigObject.ConfigData=$Policy.ExcludedSenders

            If(($Policy.ExcludedSenders).count -eq 0)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")            
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")                         
            }

            $this.AddConfig($ConfigObject)

        }

        If($PolicyExists -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object="No Policies"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            

            $this.AddConfig($ConfigObject)      
        }        

    }

}