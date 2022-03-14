using module "..\ORCA.psm1"

class ORCA114 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA114()
    {
        $this.Control=114
        $this.Area="Anti-Spam Policies"
        $this.Name="IP Allow Lists"
        $this.PassText="No IP Allow Lists have been configured"
        $this.FailRecommendation="Remove IP addresses from IP allow list"
        $this.Importance="IP addresses contained in the IP allow list are able to bypass spam, phishing and spoofing checks, potentially resulting in more spam. Ensure that the IP list is kept to a minimum."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Allowed IP"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://aka.ms/orca-antispam-action-antispam"
            "Use Anti-Spam Policy IP Allow lists"="https://aka.ms/orca-antispam-docs-3"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
    
        $CountOfPolicies = ($Config["HostedConnectionFilterPolicy"]).Count
        ForEach($HostedConnectionFilterPolicy in $Config["HostedConnectionFilterPolicy"]) 
        {
            $IsBuiltIn = $false
            $policyname = $($HostedConnectionFilterPolicy.Name)
            $IPAllowList = $($HostedConnectionFilterPolicy.IPAllowList)

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

            # Check if IPAllowList < 0 and return inconclusive for manual checking of size
            If($IPAllowList.Count -gt 0)
            {
                # IP Allow list present
                ForEach($IPAddr in @($IPAllowList)) 
                {
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.ConfigItem=$policyname
                    $ConfigObject.ConfigData=$IPAddr
                    if($IsBuiltIn)
                    {
                        $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }
                    else
                    {
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
                $ConfigObject.ConfigData="No IP detected"
                if($IsBuiltIn)
                {
                    $ConfigObject.InfoText = "This is a Built-In/Default policy managed by Microsoft and therefore cannot be edited. Other policies are set up in this area. It is being flagged only for informational purpose."
                    $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                }
                else
                {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                }
                $this.AddConfig($ConfigObject) 
            }
        }        

    }

}