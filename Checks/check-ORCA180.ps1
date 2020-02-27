using module "..\ORCA.psm1"

class ORCA180 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA180()
    {
        $this.Control=180
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Anti-spoofing protection"
        $this.PassText="Anti-phishing policy exists and EnableAntiSpoofEnforcement is true"
        $this.FailRecommendation="Enable anti-spoofing protection in Anti-phishing policy"
        $this.Importance="When the sender email address is spoofed, the message appears to originate from someone or somewhere other than the actual source. Anti-spoofing protection examines forgery of the 'From: header' which is the one that shows up in an email client like Outlook. It is recommended to enable anti-spoofing protection in Office 365 Anti-phishing policies."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Anti-spoofing protection in Office 365"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
  
        ForEach($Policy in $Config["AntiPhishPolicy"]) 
        {
            # Fail if Enabled or EnableAntiSpoofEnforcement is not set to true in any policy
            If(($Policy.Enabled -eq $true -and $Policy.EnableAntiSpoofEnforcement -eq $true) -or ($Policy.Identity -eq "Office365 AntiPhish Default" -and $Policy.EnableAntiSpoofEnforcement -eq $true))
            {
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Object=$($Policy.Name)
                    ConfigItem="EnableAntiSpoofEnforcement"
                    ConfigData=$Policy.EnableAntiSpoofEnforcement 
                    Rule="Anti-spoof protection is enabled"
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
                Rule="Anti-spoof protection is not enabled"
                Control=$this.Control
            } 
        }        

    }

}