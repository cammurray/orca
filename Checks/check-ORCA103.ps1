using module "..\ORCA.psm1"

class ORCA103 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA103()
    {
        $this.Control="ORCA-103"
        $this.Area="Content Filter Policies"
        $this.Name="Outbound spam filter policy settings"
        $this.PassText="Outbound spam filter policy settings configured"
        $this.FailRecommendation="Set RecipientLimitExternalPerHour to 500, RecipientLimitInternalPerHour to 1000, and ActionWhenThresholdReached to block."
        $this.Importance="Configure the maximum number of recipients that a user can send to, per hour for internal (RecipientLimitInternalPerHour) and external recipients (RecipientLimitExternalPerHour) and maximum number per day for outbound email. It is common, after an account compromise incident, for an attacker to use the account to generate spam and phish. Configuring the recommended values can reduce the impact, but also allows you to receive notifications when these thresholds have been reached."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Outbound Spam Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
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

            If($Policy.RecipientLimitExternalPerHour -eq 500)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="RecipientLimitExternalPerHour"
                    ConfigData=$($Policy.RecipientLimitExternalPerHour)
                    Control=$this.Control
                }                
            }
            Else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="RecipientLimitExternalPerHour"
                    ConfigData=$($Policy.RecipientLimitExternalPerHour) #the recommended setting is 500
                    Control=$this.Control
                }                            
            }
            If($Policy.RecipientLimitInternalPerHour -eq 1000)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="RecipientLimitInternalPerHour"
                    ConfigData=$($Policy.RecipientLimitInternalPerHour)
                    Control=$this.Control
                }                
            }
            Else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="RecipientLimitInternalPerHour"
                    ConfigData=$($Policy.RecipientLimitInternalPerHour) # the recommended setting is 1000"
                    Control=$this.Control
                }                            
            }
            If($Policy.RecipientLimitPerDay -eq 1000)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="RecipientLimitPerDay"
                    ConfigData=$($Policy.RecipientLimitPerDay)
                    Control=$this.Control
                }                
            }
            Else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="RecipientLimitPerDay"
                    ConfigData=$($Policy.RecipientLimitPerDay) # the recommended setting is 1000"
                    Control=$this.Control
                }                            
            }
            If($Policy.ActionWhenThresholdReached -like "BlockUser")
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object="$($Policy.Name)"
                    ConfigItem="ActionWhenThresholdReached"
                    ConfigData=$($Policy.ActionWhenThresholdReached)
                    Control=$this.Control
                }                
            }     
            Else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="ActionWhenThresholdReached"
                    ConfigData=$($Policy.ActionWhenThresholdReached) # the recommended setting is BlockUser"
                    Control=$this.Control
                }                            
            }
        }
    }

}