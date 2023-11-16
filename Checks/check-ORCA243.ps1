using module "..\ORCA.psm1"

class ORCA243 : ORCACheck
{
    <#
    
        ARC Trusted Sealers
    
    #>

    ORCA243()
    {
        $this.Control=243
        $this.Services=[ORCAService]::EOP
        $this.Area="Transport"
        $this.Name="Authenticated Receive Chain (ARC)"
        $this.PassText="Authenticated Receive Chain is set up for domains not pointing to EOP/MDO, or all domains point to EOP/MDO."
        $this.FailRecommendation="Enable Authenticated Receive Chain (ARC) trusted sealers for domains not pointed at EOP/MDO."
        $this.Importance="When EOP/MDO is behind a third-party service, sender authentication checks such as DKIM & SPF can fail. This is due to the fact that the service infront may modify the message and break the signature, or send from an IP address that is not a registered sender for the domain. By configuring the third-party to ARC seal the message, and setting up a trusted ARC sealer, the authentication results of the third-party mail relay can be used."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Domain not pointed at service"
        $this.ItemName="ARC Sealers"
        $this.DataType="Domains"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            "Improving 'Defense in Depth' with Trusted ARC Sealers for Microsoft Defender for Office 365"="https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/improving-defense-in-depth-with-trusted-arc-sealers-for/ba-p/3440707"
            "Configuring trusted ARC sealers"="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-arc-configure?view=o365-worldwide"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        # 
        $TrustedSealers = @();
        $DomainsNotAtService = @($Domain in $($Config["MXReports"] | Where-Object {$_.PointsToService -eq $False}))

        if($Config["ARCConfig"] -ne $null)
        {
            $TrustedSealers = $Config["ARCConfig"].ArcTrustedSealers.Split(",")
        }

        # Loop domains not pointing at service
        if($DomainsNotAtService -gt 0)
        {
            ForEach($DomainsNotAtService)
            {
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$Domain
                $ConfigObject.ConfigItem="Trusted Sealers"
    
                if($TrustedSealers.Count -ne 0)
                {
    
                    $ConfigObject.ConfigData=$($TrustedSealers -Join ",")
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                } else {
                    $ConfigObject.ConfigData="No Trusted Sealers"
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                }
    
                $this.AddConfig($ConfigObject)
    
            }
        } 

    }

}