using module "..\ORCA.psm1"

class ORCA103 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA103()
    {
        $this.Control="ORCA-103"
        $this.Area="Anti-Spam Policies"
        $this.Name="Outbound spam filter policy settings"
        $this.PassText="Outbound spam filter policy settings configured"
        $this.FailRecommendation="Set RecipientLimitExternalPerHour to 500, RecipientLimitInternalPerHour to 1000, and ActionWhenThresholdReached to block."
        $this.Importance="Configure the maximum number of recipients that a user can send to, per hour for internal (RecipientLimitInternalPerHour) and external recipients (RecipientLimitExternalPerHour) and maximum number per day for outbound email. It is common, after an account compromise incident, for an attacker to use the account to generate spam and phish. Configuring the recommended values can reduce the impact, but also allows you to receive notifications when these thresholds have been reached."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Outbound Spam Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
                "Security & Compliance Center - Anti-spam settings"="https://protection.office.com/antispam"
                "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
            }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedOutboundSpamFilterPolicy"])
        {

            <#
            
                RecipientLimitExternalPerHour
            
            #>
            
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Name
            $ConfigObject.ConfigItem="RecipientLimitExternalPerHour"
            $ConfigObject.ConfigData=$($Policy.RecipientLimitExternalPerHour)

            # Recipient per hour limit for standard is 500
            If($Policy.RecipientLimitExternalPerHour -eq 500)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")               
            }

            # Recipient per hour limit for strict is 400
            If($Policy.RecipientLimitExternalPerHour -eq 400)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")              
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

            <#
            
                RecipientLimitInternalPerHour
            
            #>
            
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Name
            $ConfigObject.ConfigItem="RecipientLimitInternalPerHour"
            $ConfigObject.ConfigData=$($Policy.RecipientLimitInternalPerHour)

            If($Policy.RecipientLimitInternalPerHour -eq 1000)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")               
            }

            If($Policy.RecipientLimitInternalPerHour -eq 800)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")              
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

            <#
            
                RecipientLimitPerDay
            
            #>
            
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Name
            $ConfigObject.ConfigItem="RecipientLimitPerDay"
            $ConfigObject.ConfigData=$($Policy.RecipientLimitPerDay)

            If($Policy.RecipientLimitPerDay -eq 1000)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")               
            }

            If($Policy.RecipientLimitPerDay -eq 800)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")              
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Policy.Name
            $ConfigObject.ConfigItem="ActionWhenThresholdReached"
            $ConfigObject.ConfigData=$($Policy.ActionWhenThresholdReached)

            If($Policy.ActionWhenThresholdReached -like "BlockUser")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")               
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

        }
    }

}