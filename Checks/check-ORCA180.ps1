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
        $this.ItemName="Anti Phish Policy"
        $this.DataType="Antispoof Enforced"
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

        $Enabled = $False
  
        ForEach($Policy in $Config["AntiPhishPolicy"]) 
        {
            # Fail if Enabled or EnableAntiSpoofEnforcement is not set to true in any policy
            If(($Policy.Enabled -eq $true -and $Policy.EnableAntiSpoofEnforcement -eq $true) -or ($Policy.Identity -eq "Office365 AntiPhish Default" -and $Policy.EnableAntiSpoofEnforcement -eq $true))
            {

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.ConfigItem=$($Policy.Name)
                $ConfigObject.ConfigData=$Policy.EnableAntiSpoofEnforcement
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)

                $Enabled = $True

            } 
        }

        If($Enabled -eq $False)
        {

            # No policy enabling
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem="All"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

            $this.AddConfig($ConfigObject)

        }       

    }

}