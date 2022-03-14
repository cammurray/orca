using module "..\ORCA.psm1"

class ORCA103 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA103()
    {
        $this.Control="ORCA-103"
        $this.Area="Anti-Spam Policies"
        $this.Name="Outbound spam filter policy settings"
        $this.PassText="Outbound spam filter policy settings configured"
        $this.FailRecommendation="Set RecipientLimitExternalPerHour to 500, RecipientLimitInternalPerHour to 1000, and ActionWhenThresholdReached to block."
        $this.Importance="Configure the maximum number of recipients that a user can send to, per hour for internal (RecipientLimitInternalPerHour) and external recipients (RecipientLimitExternalPerHour) and maximum number per day for outbound email. It is common, after an account compromise incident, for an attacker to use the account to generate spam and phish. Configuring the recommended values can reduce the impact, but also allows you to receive notifications when these thresholds have been reached."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Outbound Spam Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
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
        $CountOfPolicies = ($Config["HostedOutboundSpamFilterPolicy"]).Count
        ForEach($Policy in $Config["HostedOutboundSpamFilterPolicy"])
        {

            <#
            
                RecipientLimitExternalPerHour
            
            #>
            $IsBuiltIn = $false
            $policyname = $($Policy.Name)
            $RecipientLimitExternalPerHour = $($Policy.RecipientLimitExternalPerHour)
            $RecipientLimitInternalPerHour = $($Policy.RecipientLimitInternalPerHour)
            $RecipientLimitPerDay = $($Policy.RecipientLimitPerDay)
            $ActionWhenThresholdReached = $($Policy.ActionWhenThresholdReached)

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

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="RecipientLimitExternalPerHour"
            $ConfigObject.ConfigData=$RecipientLimitExternalPerHour

            # Recipient per hour limit for standard is 500
            if($IsBuiltIn)
            {
                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
            }
            else
            {
                  
             
            If($RecipientLimitExternalPerHour -eq 500)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")               
            }

            # Recipient per hour limit for strict is 400
            If($RecipientLimitExternalPerHour -eq 400)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")              
            }
        }
            # Add config to check
            $this.AddConfig($ConfigObject)

            <#
            
                RecipientLimitInternalPerHour
            
            #>
            
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="RecipientLimitInternalPerHour"
            $ConfigObject.ConfigData=$($RecipientLimitInternalPerHour)
            if($IsBuiltIn)
            {
                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
            }
            else
            {
            If($RecipientLimitInternalPerHour -eq 1000)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")               
            }

            If($RecipientLimitInternalPerHour -eq 800)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")              
            }
        }
            # Add config to check
            $this.AddConfig($ConfigObject)

            <#
            
                RecipientLimitPerDay
            
            #>
            
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="RecipientLimitPerDay"
            $ConfigObject.ConfigData=$($RecipientLimitPerDay)
            if($IsBuiltIn)
            {
                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
            }
            else
            {
            If($RecipientLimitPerDay -eq 1000)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")               
            }

            If($RecipientLimitPerDay -eq 800)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")              
            }
        }
            # Add config to check
            $this.AddConfig($ConfigObject)

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="ActionWhenThresholdReached"
            $ConfigObject.ConfigData=$($ActionWhenThresholdReached)
            if($IsBuiltIn)
            {
                $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
            }
            else
            {
            If($ActionWhenThresholdReached -like "BlockUser")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")               
            }
        }
            # Add config to check
            $this.AddConfig($ConfigObject)

        }
    }

}