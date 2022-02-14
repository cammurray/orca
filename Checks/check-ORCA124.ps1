<#

ORCA-124 Checks to determine if Safe attachments unknown malware response set to block

#>

using module "..\ORCA.psm1"

class ORCA124 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA124()
    {
        $this.Control=124
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe attachments unknown malware response"
        $this.PassText="Safe attachments unknown malware response set to block messages"
        $this.FailRecommendation="Set Safe attachments unknown malware response to block messages"
        $this.Importance="When Safe attachments unknown malware response set to block, Office 365 ATP prevents current and future messages with detected malware from proceeding and sends messages to quarantine in Office 365."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Safe Attachments Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Medium
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

        $Enabled = $False

        ForEach($Policy in $Config["SafeAttachmentsPolicy"]) 
        {
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="Action"
            $ConfigObject.ConfigData=$Policy.Action

            # Determine if ATP Safe attachments action is set to block
            If($Policy.Action -ne "Block") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            } 
            Else 
            {
                $Enabled = $True
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            If($Policy.Action -eq "Replace" -or $Policy.Action -eq "DynamicDelivery")
            {
                $Enabled = $True
                $ConfigObject.InfoText = "Attachments with detected malware will be blocked, the body of the email message delivered to the recipient."
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
            }

            $this.AddConfig($ConfigObject)
        }

        If($Enabled -eq $False)
        {

            # No policy enabling
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem="All"
            $ConfigObject.ConfigData="Enabled False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

            $this.AddConfig($ConfigObject)

        }    

    }

}