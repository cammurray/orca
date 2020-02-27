using module "..\ORCA.psm1"

class ORCA112 : ORCACheck
{
    <#
    
        Check if the Anti-spoofing policy action is configured to Move message to the recipients' Junk Email folder as per Standard security settings for Office 365 EOP/ATP
    
    #>

    ORCA112()
    {
        $this.Control="ORCA-112"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Anti-spoofing protection action"
        $this.PassText="Anti-spoofing protection action is configured to Move message to the recipients' Junk Email folders in Anti-phishing policy"
        $this.FailRecommendation="Configure Anti-spoofing protection action to Move message to the recipients' Junk Email folders in Anti-phishing policy"
        $this.Importance="When the sender email address is spoofed, the message appears to originate from someone or somewhere other than the actual source. With Standard security settings it is recommended to configure Anti-spoofing protection action to Move message to the recipients' Junk Email folders in Office 365 Anti-phishing policies."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Configuring the anti-spoofing policy"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/learn-about-spoof-intelligence?view=o365-worldwide#configuring-the-anti-spoofing-policy"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach ($Policy in $Config["AntiPhishPolicy"])
        {
            If(($Policy.Enabled -eq $true -and $Policy.AuthenticationFailAction -eq "MoveToJmf") -or ($Policy.Identity -eq "Office365 AntiPhish Default" -and $Policy.AuthenticationFailAction -eq "MoveToJmf"))
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="AuthenticationFailAction"
                    ConfigData=$Policy.AuthenticationFailAction
                    Control=$this.Control
                }
            }
            Else
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Fail"
                    Object=$($Policy.Name)
                    ConfigItem="AuthenticationFailAction"
                    ConfigData=$Policy.AuthenticationFailAction
                    Control=$this.Control
                }      
            }             
        }        

    }

}