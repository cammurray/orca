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
        $this.Services=[ORCAService]::MDO
        $this.Area="Microsoft Defender for Office 365 Policies"
        $this.Name="Safe Attachments Policy Rules"
        $this.PassText="Each domain has a Safe Attachments policy applied to it"
        $this.FailRecommendation="Apply a Safe Attachments policy to every domain"
        $this.Importance="Microsoft Defender for Office 365 Safe Attachments policies are applied using rules and evaluated by priority. To ensure coverage, scope policies so intended recipients are included (for example, accepted domains, users, or groups), and verify exceptions and rule priority so recipients are not unintentionally excluded. If policies are applied using group membership, ensure all intended users are covered. This approach can be harder to maintain, and users might be left unprotected if group memberships are incomplete or outdated. It is important not to rely only on the Built-in protection preset for Safe Attachments. Use custom or preset policies with appropriate scope and priority so intended recipients are covered."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Domain"
        $this.ItemName="Policy"
        $this.DataType="Priority"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Microsoft 365 Defender Portal - Safe attachments"="https://security.microsoft.com/safeattachmentv2"
            "Order and precedence of email protection"="https://aka.ms/orca-atpp-docs-4"
            "Recommended settings for EOP and Microsoft Defender for Office 365"="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($AcceptedDomain in $Config["AcceptedDomains"]) 
        {

            # Set up the config object

            $Rules = @()

            # Go through each Safe Attachments Policy
            # Bug fix: Previously only matched rules with an explicit RecipientDomainIs
            # containing the accepted domain. Rules with NO scoping conditions (no users,
            # groups, or domains) apply to ALL recipients by default in EOP/MDO, so they
            # should also count as covering the domain. Without this fix, tenants using
            # unscoped policies get false "No Policy Applying" failures.

            ForEach($Rule in ($Config["SafeAttachmentsRules"] | Sort-Object Priority)) 
            {
                if($Rule.State -eq "Enabled")
                {
                    # No scoping conditions (users, groups, domains) = all recipients
                    $NoConditions = ($null -eq $Rule.RecipientDomainIs -or $Rule.RecipientDomainIs.Count -eq 0) -and ($null -eq $Rule.SentTo -or $Rule.SentTo.Count -eq 0) -and ($null -eq $Rule.SentToMemberOf -or $Rule.SentToMemberOf.Count -eq 0)
                    $ExplicitDomainMatch = $Rule.RecipientDomainIs -contains $AcceptedDomain.Name
                    $NotExcluded = ($Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name) -and ($null -eq $Rule.ExceptIfSentToMemberOf) -and ($null -eq $Rule.ExceptIfSentTo)

                    if(($ExplicitDomainMatch -or $NoConditions) -and $NotExcluded)
                    {
                        # Policy applies to this domain

                        $Rules += New-Object -TypeName PSObject -Property @{
                            PolicyName=$($Rule.SafeAttachmentPolicy)
                            Priority=$($Rule.Priority)
                        }

                    }
                }

            }
            # Same empty-scoping fix applies to preset protection policy rules
            ForEach($Rule in ($Config["ATPProtectionPolicyRule"] | Sort-Object Priority)) 
            {
                if(($Rule.SafeAttachmentPolicy -ne "") -and ($null -ne $Rule.SafeAttachmentPolicy ))
                { 
                   if($Rule.State -eq "Enabled")
                   {
                        # No scoping conditions (users, groups, domains) = all recipients
                        $NoConditions = ($null -eq $Rule.RecipientDomainIs -or $Rule.RecipientDomainIs.Count -eq 0) -and ($null -eq $Rule.SentTo -or $Rule.SentTo.Count -eq 0) -and ($null -eq $Rule.SentToMemberOf -or $Rule.SentToMemberOf.Count -eq 0)
                        $ExplicitDomainMatch = $Rule.RecipientDomainIs -contains $AcceptedDomain.Name
                        $NotExcluded = ($Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name) -and ($null -eq $Rule.ExceptIfSentToMemberOf) -and ($null -eq $Rule.ExceptIfSentTo)

                        if(($ExplicitDomainMatch -or $NoConditions) -and $NotExcluded)
                        {
                            # Policy applies to this domain

                            $Rules += New-Object -TypeName PSObject -Property @{
                            PolicyName=$($Rule.SafeAttachmentPolicy)
                            Priority=$($Rule.Priority)
                            }

                        }   
                    }
                }
            }

            If($Rules.Count -gt 0)
            {
                $Count = 0
                $CountOfPolicies = ($Rules).Count
                ForEach($r in ($Rules | Sort-Object Priority))
                {
                    $IsBuiltIn = $false
                    $policyname = $($r.PolicyName)
                    $priority =$($r.Priority)
                    if($policyname -match "Built-In" -and $CountOfPolicies -gt 1)
                    {
                        $IsBuiltIn =$True
                        $policyname = "$policyname" +" [Built-In]"
                    }
                    elseif(($policyname -eq "Default" -or $policyname -eq "Office365 AntiPhish Default") -and $CountOfPolicies -gt 1)
                    {
                        $IsBuiltIn =$True
                        $policyname = "$policyname" +" [Default]"
                    }

                    $Count++

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$($AcceptedDomain.Name)
                    $ConfigObject.ConfigItem=$policyname
                    $ConfigObject.ConfigData=$priority

                    If($Count -eq 1)
                    {
                        # First policy based on priority is a pass
                        if($IsBuiltIn)
                        {
                            $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                            $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                        }
                        else
                        {
                            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                        }
                    }
                    else
                    {
                        if($IsBuiltIn)
                        {
                            $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                            $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                        }
                        else
                        {
                        # Additional policies based on the priority should be listed as informational
                            $ConfigObject.InfoText = "There are multiple policies that apply to this domain, only the policy with the lowest priority will apply. This policy may not apply based on a lower priority."
                            $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                        }
                    } 

                    $this.AddConfig($ConfigObject)
                }
            } 
            elseif($Rules.Count -eq 0)
            {
                # No policy is applying to this domain

                $ConfigObject = [ORCACheckConfig]::new()

                $ConfigObject.Object=$($AcceptedDomain.Name)
                $ConfigObject.ConfigItem="No Policy Applying"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")            
    
                $this.AddConfig($ConfigObject)     
            }

        }

    }

}