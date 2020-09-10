using module "..\ORCA.psm1"

class ORCA118_3 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA118_3()
    {
        $this.Control="ORCA-118-3"
        $this.Area="Anti-Spam Policies"
        $this.Name="Domain Whitelisting"
        $this.PassText="Your own domains are not being allow listed in an unsafe manner"
        $this.FailRecommendation="Remove allow listing on domains belonging to your organisation"
        $this.Importance="Emails coming from whitelisted domains bypass several layers of protection within Exchange Online Protection. When allow listing your own domains, an attacker can spoof any account in your organisation that has this domain. This is a significant phishing attack vector."
        $this.ExpandResults=$True
        $this.ItemName="Anti-Spam Policy"
        $this.DataType="Organisation Domain Allow Listed"
        $this.ChiValue=[ORCACHI]::VeryHigh
        $this.Links= @{
            "Security & Compliance Center - Anti-spam settings"="https://protection.office.com/antispam"
            "Use Anti-Spam Policy Sender/Domain Allow lists"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/create-safe-sender-lists-in-office-365#use-anti-spam-policy-senderdomain-allow-lists"
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

                    # Is this domain an organisation domain?
                    If(@($Config["AcceptedDomains"] | Where-Object {$_.Name -eq $Domain}).Count -gt 0)
                    {
                        # Check objects
                        $ConfigObject = [ORCACheckConfig]::new()
                        $ConfigObject.ConfigItem=$($Policy.Name)
                        $ConfigObject.ConfigData=$Domain
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                        $this.AddConfig($ConfigObject) 
                    } 
                }
            } 
        }        
    }

}