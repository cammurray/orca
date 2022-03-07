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
        $this.PassText="Anti-phishing policy exists and EnableSpoofIntelligence is true"
        $this.FailRecommendation="Enable anti-spoofing protection in Anti-phishing policy"
        $this.Importance="When the sender email address is spoofed, the message appears to originate from someone or somewhere other than the actual source. Anti-spoofing protection examines forgery of the 'From: header' which is the one that shows up in an email client like Outlook. It is recommended to enable anti-spoofing protection in Office 365 Anti-phishing policies."
        $this.ExpandResults=$True
        $this.ItemName="Anti Phish Policy"
        $this.DataType="Antispoof Enforced"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Anti-spoofing protection in Office 365"="https:/aka.ms/orca-atpp-docs-3"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $Enabled = $False
        #$CountOfPolicies = ($Config["AntiPhishPolicy"]).Count
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
      
        ForEach($Policy in $Config["AntiPhishPolicy"]) 
        {
            $IsPolicyDisabled = $false
            $EnableSpoofIntelligence = $($Policy.EnableSpoofIntelligence)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)
            $Enabled =$($Policy.Enabled)
            $Identity = $($Policy.Identity)
            ForEach($data in ($global:AntiSpamPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" +" [Disabled]"
                $EnableSpoofIntelligence = "N/A"
            }
            elseif($policyname -match "Built-In" -and $CountOfPolicies -gt 1)
            {
                $IsBuiltIn =$True
                $policyname = "$policyname" +" [Built-In]"
            }
            elseif(($policyname -eq "Default" -or $policyname -eq "Office365 AntiPhish Default") -and $CountOfPolicies -gt 1)
            {
                $IsBuiltIn =$True
                $policyname = "$policyname" +" [Default]"
            }
            # Fail if Enabled or EnableSpoofIntelligence is not set to true in any policy
            If(($Enabled -eq $true -and $EnableSpoofIntelligence -eq $true) -or ($Identity -eq "Office365 AntiPhish Default" -and $EnableSpoofIntelligence -eq $true))
            {

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.ConfigItem=$policyname
                $ConfigObject.ConfigData=$EnableSpoofIntelligence
                if($IsPolicyDisabled)
                    {
                        $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    elseif($IsBuiltIn)
                    {
                        $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    else
                       {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                       }

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