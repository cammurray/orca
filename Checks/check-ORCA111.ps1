using module "..\ORCA.psm1"

class ORCA111 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA111()
    {
        $this.Control="ORCA-111"
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Unauthenticated Sender (tagging)"
        $this.PassText="Anti-phishing policy exists and EnableUnauthenticatedSender is true"
        $this.FailRecommendation="Enable unauthenticated sender tagging in Anti-phishing policy"
        $this.Importance="When the sender email address is spoofed, the message appears to originate from someone or somewhere other than the actual source. It is recommended to enable unauthenticated sender tagging in Office 365 Anti-phishing policies. The feature apply a '?' symbol in Outlook's sender card if the sender fails authentication checks."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-phishing"="https://aka.ms/orca-atpp-action-antiphishing"
            "Unverified Sender"="https://aka.ms/orca-atpp-docs-12"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["AntiPhishPolicy"] ).Count
        $CountOfPolicies = ($global:AntiSpamPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach ($Policy in $Config["AntiPhishPolicy"])
        {

            $IsPolicyDisabled = $false
            $EnableUnauthenticatedSender = $($Policy.EnableUnauthenticatedSender)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)
            $identity = $($Policy.Identity)
            $enabled = $($Policy.Enabled)

            ForEach($data in ($global:AntiSpamPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableUnauthenticatedSender"
            $ConfigObject.ConfigData=$EnableUnauthenticatedSender
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset

            If(($enabled -eq $true -and $EnableUnauthenticatedSender -eq $true) -or ($identity -eq "Office365 AntiPhish Default" -and $EnableUnauthenticatedSender -eq $true))
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