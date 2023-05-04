using module "..\ORCA.psm1"

class ORCA139 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA139()
    {
        $this.Control=139
        $this.Area="Anti-Spam Policies"
        $this.Name="Spam Action"
        $this.PassText="Spam action set to move message to junk mail folder or quarantine"
        $this.FailRecommendation="Change Spam action to move message to Junk Email Folder"
        $this.Importance="It is recommended to configure Spam detection action to Move messages to Junk Email folder."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Action"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
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
            $SpamAction = $($Policy.SpamAction)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            ForEach($data in ($global:HostedContentPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$($SpamAction)
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled
            
            # For standard, this should be MoveToJmf
            If($SpamAction -ne "MoveToJmf") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            # For strict, this should be Quarantine
            If($SpamAction -ne "Quarantine") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }

            # For either Delete or Redirect we should raise an informational
            If($SpamAction -eq "Delete" -or $SpamAction -eq "Redirect")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($SpamAction) option may impact the users ability to release emails and may impact user experience."
            }
            
            $this.AddConfig($ConfigObject)
            
        }        

    }

}