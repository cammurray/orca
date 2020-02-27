using module "..\ORCA.psm1"

class ORCA118_2 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA118_2()
    {
        $this.Control="118-2"
        $this.Area="Transport Rules"
        $this.Name="Domain Whitelisting"
        $this.PassText="Domains are not being whitelisted in an unsafe manner"
        $this.FailRecommendation="Remove whitelisting on domains"
        $this.Importance="Emails coming from whitelisted domains bypass several layers of protection within Exchange Online Protection. If domains are whitelisted, they are open to being spoofed from malicious actors."
        $this.ExpandResults=$True
        $this.ItemName="Transport Rule"
        $this.DataType="Whitelisted Domain"
        $this.Links= @{
            "Using Exchange Transport Rules (ETRs) to allow specific senders"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/create-safe-sender-lists-in-office-365#using-exchange-transport-rules-etrs-to-allow-specific-senders-recommended"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $Check = "Transport Rule SCL"
    
        # Look through Transport Rule for an action SetSCL -1
    
        ForEach($TransportRule in $Config["TransportRules"]) {
            If($TransportRule.SetSCL -eq "-1") {
                #Rules that apply to the sender domain
                #From Address notmatch is to include if just domain name is value
                If($TransportRule.SenderDomainIs -ne $null -or ($TransportRule.FromAddressContainsWords -ne $null -and $TransportRule.FromAddressContainsWords -notmatch ".+@") -or ($TransportRule.FromAddressMatchesPatterns -ne $null -and $TransportRule.FromAddressMatchesPatterns -notmatch ".+@")){
                    #Look for condition that checks auth results header and its value
                    If(($TransportRule.HeaderContainsMessageHeader -eq 'Authentication-Results' -and $TransportRule.HeaderContainsWords -ne $null) -or ($TransportRule.HeaderMatchesMessageHeader -like '*Authentication-Results*' -and $TransportRule.HeaderMatchesPatterns -ne $null)) {
                        # OK
                    }
                    #Look for exception that checks auth results header and its value 
                    elseif(($TransportRule.ExceptIfHeaderContainsMessageHeader -eq 'Authentication-Results' -and $TransportRule.ExceptIfHeaderContainsWords -ne $null) -or ($TransportRule.ExceptIfHeaderMatchesMessageHeader -like '*Authentication-Results*' -and $TransportRule.ExceptIfHeaderMatchesPatterns -ne $null)) {
                        # OK
                    }
                    elseif($TransportRule.SenderIpRanges -ne $null) {
                        # OK
                    }
                    #Look for condition that checks for any other header and its value
                    else {
                        ForEach($RuleDomain in $($TransportRule.SenderDomainIs)) {
                            $this.Results +=  New-Object -TypeName psobject -Property @{
                                Result="Fail"
                                Check=$Check
                                ConfigItem=$($TransportRule.Name)
                                ConfigData=$($RuleDomain)
                                Rule="SetSCL -1 action for sender domain but no check for auth results header, sender IP, or other header"
                                Control=$this.Control
                            }
                        }
                        ForEach($FromAddressContains in $($TransportRule.FromAddressContainsWords)) {
                            $this.Results +=  New-Object -TypeName psobject -Property @{
                                Result="Fail"
                                Check=$Check
                                ConfigItem=$($TransportRule.Name)
                                ConfigData="Contains $($FromAddressContains)"
                                Rule="SetSCL -1 action for sender domain but no check for auth results header, sender IP, or other header"
                                Control=$this.Control
                            }
                        }
                        ForEach($FromAddressMatch in $($TransportRule.FromAddressMatchesPatterns)) {
                            $this.Results +=  New-Object -TypeName psobject -Property @{
                                Result="Fail"
                                Check=$Check
                                ConfigItem=$($TransportRule.Name)
                                ConfigData="Matches $($FromAddressMatch)"
                                Rule="SetSCL -1 action for sender domain but no check for auth results header, sender IP, or other header"
                                Control=$this.Control
                            }
                        }
    
                    }
                }
                #No sender domain restriction, so check for IP restriction
                elseif($null -ne $TransportRule.SenderIpRanges) {
                    ForEach($SenderIpRange in $TransportRule.SenderIpRanges) {
                        $this.Results +=  New-Object -TypeName psobject -Property @{
                            Result="Fail"
                            Check=$Check
                            ConfigItem=$($TransportRule.Name)
                            ConfigData=$SenderIpRange
                            Rule="SetSCL -1 action with IP condition but not limiting sender domain"
                            Control=$this.Control
                        }
                    }
                }
                #No sender restriction, so check for condition that checks auth results header and its value
                elseif(($TransportRule.HeaderContainsMessageHeader -eq 'Authentication-Results' -and $TransportRule.HeaderContainsWords -ne $null) -or ($TransportRule.HeaderMatchesMessageHeader -like '*Authentication-Results*' -and $TransportRule.HeaderMatchesPatterns -ne $null)) {
                    # OK
                }
                #No sender restriction, so check for exception that checks auth results header and its value 
                elseif(($TransportRule.ExceptIfHeaderContainsMessageHeader -eq 'Authentication-Results' -and $TransportRule.ExceptIfHeaderContainsWords -ne $null) -or ($TransportRule.ExceptIfHeaderMatchesMessageHeader -like '*Authentication-Results*' -and $TransportRule.ExceptIfHeaderMatchesPatterns -ne $null)) {
                    # OK
                }
            }
        }
        # If no rules found with SetSCL -1, then pass.
    
        if($this.Results.Count -eq 0) {
            $this.Results +=  New-Object -TypeName psobject -Property @{
                Result="Pass"
                Check=$Check
                ConfigItem="Transport Rules"
                Rule="No SetSCL -1 actions found"
                Control=$this.Control
            }  
        }            

    }

}