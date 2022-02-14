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
    
        ForEach($HostedConnectionFilterPolicy in $Config["HostedConnectionFilterPolicy"]) 
        {


            # Check if IPAllowList < 0 and return inconclusive for manual checking of size
            If($HostedConnectionFilterPolicy.IPAllowList.Count -gt 0)
            {
                # IP Allow list present
                ForEach($IPAddr in @($HostedConnectionFilterPolicy.IPAllowList)) 
                {
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.ConfigItem=$($HostedConnectionFilterPolicy.Name)
                    $ConfigObject.ConfigData=$IPAddr
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    $this.AddConfig($ConfigObject)  
                }
    
            } 
            else 
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.ConfigItem=$($HostedConnectionFilterPolicy.Name)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                $this.AddConfig($ConfigObject) 
            }
        }        

    }

}