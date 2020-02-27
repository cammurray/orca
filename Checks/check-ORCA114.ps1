using module "..\ORCA.psm1"

class ORCA114 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA114()
    {
        $this.Control=114
        $this.Area="Content Filter Policies"
        $this.Name="IP Allow Lists"
        $this.PassText="No IP Allow Lists have been configured"
        $this.FailRecommendation="Remove IP addresses from IP allow list"
        $this.Importance="IP addresses contained in the IP allow list are able to bypass spam, phishing and spoofing checks, potentially resulting in more spam. Ensure that the IP list is kept to a minimum."
        $this.ExpandResults=$True
        $this.ItemName="Content Filter Policy"
        $this.DataType="Allowed IP"
        $this.Links= @{
            "Use Anti-Spam Policy IP Allow lists"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/create-safe-sender-lists-in-office-365#use-anti-spam-policy-ip-allow-lists"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $Check = "IP Allow List Size"
    
        ForEach($HostedConnectionFilterPolicy in $Config["HostedConnectionFilterPolicy"]) 
        {
            # Check if IPAllowList < 0 and return inconclusive for manual checking of size
            If($HostedConnectionFilterPolicy.IPAllowList.Count -gt 0)
            {
                # IP Allow list present
                ForEach($IPAddr in @($HostedConnectionFilterPolicy.IPAllowList)) 
                {
                    $this.Results += New-Object -TypeName psobject -Property @{
                        Result="Fail"
                        Check=$Check
                        ConfigItem=$($HostedConnectionFilterPolicy.Name)
                        ConfigData=$IPAddr
                        Rule="IP Allow List contains too many IPs"
                        Control=$this.Control
                    }    
                }
    
            } 
            else 
            {
                # IPAllowList is blank, so pass.
                $this.Results += New-Object -TypeName psobject -Property @{
                    Result="Pass"
                    Check=$Check
                    ConfigItem=$($HostedConnectionFilterPolicy.Name)
                    ConfigData="IP Entries $($HostedConnectionFilterPolicy.IPAllowList.Count)"
                    Rule="IP Allow List empty"
                    Control=$this.Control
                }
            }
        }        

    }

}