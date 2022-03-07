using module "..\ORCA.psm1"

class ORCA118_1 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA118_1()
    {
        $this.Control="ORCA-118-1"
        $this.Area="Anti-Spam Policies"
        $this.Name="Domain Whitelisting"
        $this.PassText="Domains are not being whitelisted in an unsafe manner"
        $this.FailRecommendation="Remove whitelisting on domains"
        $this.Importance="Emails coming from whitelisted domains bypass several layers of protection within Exchange Online Protection. If domains are whitelisted, they are open to being spoofed from malicious actors."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Whitelisted Domain"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Use Anti-Spam Policy Sender/Domain Allow lists"="https://aka.ms/orca-antispam-docs-4"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"] ).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {
            $IsPolicyDisabled = $false

            $IsBuiltIn = $false
            $policyname = $($Policy.Name)
            $AllowedSenderDomains = $($Policy.AllowedSenderDomains)
            ForEach($data in ($global:HostedContentPolicyStatus | Where-Object {$_.PolicyName -eq $policyname})) 
            {
                $IsPolicyDisabled = !$data.IsEnabled
            }

            if($IsPolicyDisabled)
            {
                $IsPolicyDisabled = $true
                $policyname = "$policyname" +" [Disabled]"
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
    
            # Fail if AllowedSenderDomains is not null
    
            If(($AllowedSenderDomains).Count -gt 0) 
            {
                ForEach($Domain in $AllowedSenderDomains) 
                {
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.ConfigItem=$policyname
                    
                    if($IsPolicyDisabled)
                    {
                        $ConfigObject.ConfigData="N/A"
                        $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    elseif($IsBuiltIn)
                    {
                        $ConfigObject.ConfigData=$($Domain.Domain)
                        $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    else
                       {
                        $ConfigObject.ConfigData=$($Domain.Domain)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                       }
                    $this.AddConfig($ConfigObject)  
                }
            } 
            else 
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.ConfigItem=$policyname
                
                if($IsPolicyDisabled)
                {
                    $ConfigObject.ConfigData="N/A"
                    $ConfigObject.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is properly set according to this check. It is being flagged incase of accidental enablement."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                elseif($IsBuiltIn)
                {
                    $ConfigObject.ConfigData="No domain available"
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                   {
                    $ConfigObject.ConfigData="No domain available"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                   }
                $this.AddConfig($ConfigObject)  
            }
        }        
    }

}