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

        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {
    
            # Fail if AllowedSenderDomains is not null
    
            If(($Policy.AllowedSenderDomains).Count -gt 0) 
            {
                ForEach($Domain in $Policy.AllowedSenderDomains) 
                {
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.ConfigItem=$($Policy.Name)
                    $ConfigObject.ConfigData=$($Domain.Domain)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    $this.AddConfig($ConfigObject)  
                }
            } 
            else 
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.ConfigItem=$($Policy.Name)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                $this.AddConfig($ConfigObject)  
            }
        }        
    }

}