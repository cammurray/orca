using module "..\ORCA.psm1"

class ORCA101 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA101()
    {
        $this.Control="ORCA-101"
        $this.Area="Anti-Spam Policies"
        $this.Name="Mark Bulk as Spam"
        $this.PassText="Bulk is marked as spam"
        $this.FailRecommendation="Set the anti-spam policy to mark bulk mail as spam"
        $this.Importance="The differentiation between bulk and spam can sometimes be subjective. The bulk complaint level is based on the number of complaints from the sender. Marking bulk as spam can decrease the amount of perceived spam received. This setting is only available in PowerShell."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Mark as Spam Bulk Mail Setting (MarkAsSpamBulkMail)"
        $this.ChiValue = [ORCACHI]::Low
        $this.Links= @{
            "Set-HostedContentFilterPolicy"="https://aka.ms/orca-antispam-docs-9"
            "Recommended settings for EOP and Office 365 ATP security"="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            $IsPolicyDisabled = $false
            $MarkAsSpamBulkMail = $($Policy.MarkAsSpamBulkMail)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:HostedContentPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$MarkAsSpamBulkMail
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset

            If($MarkAsSpamBulkMail -eq "On")
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