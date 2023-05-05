using module "..\ORCA.psm1"

class ORCA141 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA141()
    {
        $this.Control=141
        $this.Area="Anti-Spam Policies"
        $this.Name="Bulk Action"
        $this.PassText="Bulk action set to Move message to Junk Email Folder"
        $this.FailRecommendation="Change bulk action to move messages to junk mail folder"
        $this.Importance="It is recommended to configure Bulk detection action to Move messages to Junk Email folder."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Action"
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
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $BulkSpamAction = $($Policy.BulkSpamAction)

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled

            # For standard Fail if BulkSpamAction is not set to MoveToJmf
    
            If($BulkSpamAction -ne "MoveToJmf") 
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            } 
            else 
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            # For strict Fail if BulkSpamAction is not set to Quarantine

            If($BulkSpamAction -ne "Quarantine") 
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            } 
            else 
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }

            # For either Delete or Quarantine we should raise an informational

            If($BulkSpamAction -eq "Delete" -or $BulkSpamAction -eq "Redirect")
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($BulkSpamAction) option may impact the users ability to release emails and may impact user experience."
            }
            
            $this.AddConfig($ConfigObject)

        }        

    }

}