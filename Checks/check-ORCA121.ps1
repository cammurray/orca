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
            "Security & Compliance Center - Anti-spam settings"="https://protection.office.com/antispam"
            "Zero-hour auto purge - protection against spam and malware"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/zero-hour-auto-purge"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
            
            # Check requirement of Spam ZAP - MoveToJmf, redirect, delete, quarantine

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="SpamAction"
            $ConfigObject.ConfigData=$($Policy.SpamAction)

            If($Policy.SpamAction -eq "MoveToJmf" -or $Policy.SpamAction -eq "Redirect" -or $Policy.SpamAction -eq "Delete" -or $Policy.SpamAction -eq "Quarantine") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            $this.AddConfig($ConfigObject)

            # Check requirement of Phish ZAP - MoveToJmf, redirect, delete, quarantine

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$($Policy.Name)
            $ConfigObject.ConfigItem="PhishSpamAction"
            $ConfigObject.ConfigData=$($Policy.PhishSpamAction)

            If($Policy.PhishSpamAction -eq "MoveToJmf" -or $Policy.PhishSpamAction -eq "Redirect" -or $Policy.PhishSpamAction -eq "Delete" -or $Policy.PhishSpamAction -eq "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            $this.AddConfig($ConfigObject)
    
        }        

    }

}