<#

224 - Check ATP Phishing Mailbox Intelligence Action 

#>

using module "..\ORCA.psm1"

class ORCA224 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA224()
    {
        $this.Control=224
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Mailbox Intelligence Action"
        $this.PassText="Your policy is configured to notify users with a tip."
        $this.FailRecommendation="Enable tips so that users can receive visible indication on incoming messages."
        $this.Importance="Mailbox Intelligence checks can provide your users with intelligence on suspicious incoming emails that appear to be from users that they normally communicate with based on their graph."
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

            #  Determine if tips for user impersonation is on

            If($Policy.EnableSimilarUsersSafetyTips -eq $false)
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="EnableSimilarUsersSafetyTips"
                    ConfigData=$($Policy.EnableSimilarUsersSafetyTips)
                    Control=$this.Control
                }  
            }
            else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="EnableSimilarUsersSafetyTips"
                    ConfigData=$($Policy.EnableSimilarUsersSafetyTips)
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
                Control=$this.Control
            }        
        }             

    }

}