<#

227 - Check Safe Attachments Policy Exists for all domains

#>

using module "..\ORCA.psm1"

class ORCA227 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA227()
    {
        $this.Control=227
        $this.Services=[ORCAService]::OATP
        $this.Area="Advanced Threat Protection Policies"
        $this.Name="Safe Attachments Policy Rules"
        $this.PassText="Each domain has a Safe Attachments policy applied to it"
        $this.FailRecommendation="Apply a Safe Attachments policy to every domain"
        $this.Importance="Office 365 ATP Safe Attachments policies are applied using rules. The recipient domain condition is the most effective way of applying the Safe Attachments policy, ensuring no users are left without protection."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Domain"
        $this.ItemName="Policy"
        $this.DataType="Priority"
        $this.Links= @{
            "Security & Compliance Center - Safe attachments"="https://protection.office.com/safeattachment"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#office-365-advanced-threat-protection-security"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($AcceptedDomain in $Config["AcceptedDomains"]) 
        {
    
            #$AcceptedDomain.Name

            $DomainPolicyExists = $False

            # Set up the config object
            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$($AcceptedDomain.Name)

            # Go through each Safe Links Policy

            ForEach($Rule in ($Config["SafeAttachmentsRules"] | Sort-Object Priority)) 
            {
                if($null -eq $Rule.SentTo -and $null -eq $Rule.SentToMemberOf -and $Rule.State -eq "Enabled")
                {
                    if($Rule.RecipientDomainIs -contains $AcceptedDomain.Name -and $Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name)
                    {
                        # Policy applies to this domain

                        $DomainPolicyExists = $True

                        $ConfigObject.ConfigItem=$($Rule.SafeAttachmentPolicy)
                        $ConfigObject.ConfigData=$($Rule.Priority)
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                        $this.AddConfig($ConfigObject)
                    }
                }

            }

            if($DomainPolicyExists -eq $False)
            {
                # No policy is applying to this domain

                $ConfigObject.ConfigItem="No Policy Applying"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            
    
                $this.AddConfig($ConfigObject)     
            }

        }

    }

}