using module "..\ORCA.psm1"

class ORCA121 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA121()
    {
        $this.Control=121
        $this.Area="Zero Hour Autopurge"
        $this.Name="Supported filter policy action"
        $this.PassText="Supported filter policy action used"
        $this.FailRecommendation="Change filter policy action to support Zero Hour Auto Purge"
        $this.Importance="Zero Hour Autopurge can assist removing false-negatives post detection from mailboxes. It requires a supported action in the spam filter policy."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ChiValue=[ORCACHI]::VeryHigh
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Action"
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Zero-hour auto purge - protection against spam and malware"="https://aka.ms/orca-zha-docs-2"
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
            $SpamAction = $($Policy.SpamAction)
            $PhishSpamAction =$($Policy.PhishSpamAction)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:HostedContentPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            # Check requirement of Spam ZAP - MoveToJmf, redirect, delete, quarantine

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="SpamAction"
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled

            If($SpamAction -eq "MoveToJmf" -or $SpamAction -eq "Redirect" -or $SpamAction -eq "Delete" -or $SpamAction -eq "Quarantine") 
            {
                $ConfigObject.ConfigData=$SpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.ConfigData=$SpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            $this.AddConfig($ConfigObject)

            # Check requirement of Phish ZAP - MoveToJmf, redirect, delete, quarantine

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="PhishSpamAction"
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled

            If($PhishSpamAction -eq "MoveToJmf" -or $PhishSpamAction -eq "Redirect" -or $PhishSpamAction -eq "Delete" -or $PhishSpamAction -eq "Quarantine")
            {
                $ConfigObject.ConfigData=$PhishSpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.ConfigData=$PhishSpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            $this.AddConfig($ConfigObject)
    
        }        

    }

}