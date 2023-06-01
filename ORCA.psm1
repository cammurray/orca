#Requires -Version 5.1

<#
	.SYNOPSIS
		The Office 365 Recommended Configuration Analyzer (ORCA)

	.DESCRIPTION
       

	.NOTES
		Cam Murray
		Senior Program Manager - Microsoft
        camurray@microsoft.com
        
        Daniel Mozes
        Senior Program Manager - Microsoft
        damozes@microsoft.com

        Output report uses open source components for HTML formatting
        - bootstrap - MIT License - https://getbootstrap.com/docs/4.0/about/license/
        - fontawesome - CC BY 4.0 License - https://fontawesome.com/license/free
        
        ############################################################################

        This sample script is not supported under any Microsoft standard support program or service. 
        This sample script is provided AS IS without warranty of any kind. 
        Microsoft further disclaims all implied warranties including, without limitation, any implied 
        warranties of merchantability or of fitness for a particular purpose. The entire risk arising 
        out of the use or performance of the sample script and documentation remains with you. In no
        event shall Microsoft, its authors, or anyone else involved in the creation, production, or 
        delivery of the scripts be liable for any damages whatsoever (including, without limitation, 
        damages for loss of business profits, business interruption, loss of business information, 
        or other pecuniary loss) arising out of the use of or inability to use the sample script or
        documentation, even if Microsoft has been advised of the possibility of such damages.

        ############################################################################    

	.LINK
        about_functions_advanced

#>
[System.Collections.ArrayList] $global:SafeLinkPolicyStatus = [System.Collections.ArrayList] @()
[System.Collections.ArrayList] $global:SafeAttachmentsPolicyStatus = [System.Collections.ArrayList] @()
[System.Collections.ArrayList] $global:MalwarePolicyStatus = [System.Collections.ArrayList] @()
[System.Collections.ArrayList] $global:AntiSpamPolicyStatus = [System.Collections.ArrayList] @()
[System.Collections.ArrayList] $global:HostedContentPolicyStatus = [System.Collections.ArrayList] @()


function Get-ORCADirectory
{
    <#

        Gets or creates the ORCA directory in AppData
        
    #>

    If($IsWindows)
    {
        $Directory = "$($env:LOCALAPPDATA)\Microsoft\ORCA"
    }
    elseif($IsLinux -or $IsMacOS)
    {
        $Directory = "$($env:HOME)/ORCA"
    }
    else 
    {
        $Directory = "$($env:LOCALAPPDATA)\Microsoft\ORCA"
    }

    If(Test-Path $Directory) 
    {
        Return $Directory
    } 
    else 
    {
        New-Item -Type Directory $Directory | out-null
        Return $Directory
    }

}

Function Invoke-ORCAConnections
{
    Param
    (
        [String]$ExchangeEnvironmentName,
        [String]$DelegatedOrganization,
        [Boolean]$Install
    )
    <#
    
    Check which module is loaded and then run the respective connection
    
    #>

    If(Get-Command "Connect-ExchangeOnline" -ErrorAction:SilentlyContinue)
    {
        Write-Host "$(Get-Date) Connecting to Exchange Online (Modern Module).."

        if($DelegatedOrganization -eq $null)
        {
            Connect-ExchangeOnline -ExchangeEnvironmentName $ExchangeEnvironmentName -WarningAction:SilentlyContinue | Out-Null
        } else 
        {
            Connect-ExchangeOnline -ExchangeEnvironmentName $ExchangeEnvironmentName -WarningAction:SilentlyContinue -DelegatedOrganization $DelegatedOrganization | Out-Null
        }
        
    }
    ElseIf(Get-Command "Connect-EXOPSSession" -ErrorAction:SilentlyContinue)
    {

        # Cannot use Delegated Organization connecting this way, potentially we should deprecate this way of connecting
        if($DelegatedOrganization -ne $null)
        {
            throw "Cannot use DelegatedOrganization without Exchange Online PowerShell module installed."
        }

        Write-Host "$(Get-Date) Connecting to Exchange Online.."
        Connect-EXOPSSession -PSSessionOption $ProxySetting -WarningAction:SilentlyContinue | Out-Null    
    } 
    Else 
    {
        If($Install)
        {
            Try
            {
                #  Try installing ExchangeOnlineManagement module in to CurrentUser scope
                Write-Host "$(Get-Date) Exchange Online Management module is missing - attempting to install in to CurrentUser scope.. (You may be asked to trust the PS Gallery)"
                Install-Module ExchangeOnlineManagement -ErrorAction:SilentlyContinue -Scope CurrentUser

                # Then connect..
                Connect-ExchangeOnline -ExchangeEnvironmentName $ExchangeEnvironmentName -WarningAction:SilentlyContinue  | Out-Null

                $Installed = $True
            }
            catch
            {
                $Installed = $False
            }
        }

        if(!$Installed)
        {
            # Error if not installed
            Throw "ORCA requires either the Exchange Online PowerShell Module (aka.ms/exopsmodule) loaded or the Exchange Online PowerShell module from the PowerShell Gallery installed."
        }
    }

    # Perform check for Exchange Connection Status
    If($(Get-EXConnectionStatus) -eq $False)
    {
        Throw "ORCA was unable to connect to Exchange Online, or you do not have sufficient permissions to check ORCA related configuration."
    }
}

enum CheckType
{
    ObjectPropertyValue
    PropertyValue
}

[Flags()]
enum ORCAService
{
    EOP = 1
    OATP = 2
}

enum ORCAConfigLevel
{
    None = 0
    Informational = 4
    Standard = 5
    Strict = 10
    TooStrict = 15
}

enum ORCAResult
{
    Pass = 1
    Informational = 2
    Fail = 3
}

enum ORCACHI
{
    NotRated = 0
    Low = 5
    Medium = 10
    High = 15
    VeryHigh = 20
    Critical = 100
}

enum PolicyType
{
    Malware
    Spam
    Antiphish
    SafeAttachments
    SafeLinks
    OutboundSpam
}

enum PresetPolicyLevel
{
    None = 0
    Strict = 1
    Standard = 2
}

Class ORCACheckConfig
{

    ORCACheckConfig()
    {
        # Constructor

        $this.Results = @()

        $this.Results += New-Object -TypeName ORCACheckConfigResult -Property @{
            Level=[ORCAConfigLevel]::Informational
        }

        $this.Results += New-Object -TypeName ORCACheckConfigResult -Property @{
            Level=[ORCAConfigLevel]::Standard
        }

        $this.Results += New-Object -TypeName ORCACheckConfigResult -Property @{
            Level=[ORCAConfigLevel]::Strict
        }

        $this.Results += New-Object -TypeName ORCACheckConfigResult -Property @{
            Level=[ORCAConfigLevel]::TooStrict
        }
    }

    # Set the result for this mode
    SetResult([ORCAConfigLevel]$Level,$Result)
    {
        ($this.Results | Where-Object {$_.Level -eq $Level}).Value = $Result

        # The level of this configuration should be its strongest result (e.g if its currently standard and we have a strict pass, we should make the level strict)
        if($Result -eq "Pass" -and ($this.Level -lt $Level -or $this.Level -eq [ORCAConfigLevel]::None))
        {
            $this.Level = $Level
        } 
        elseif ($Result -eq "Fail" -and ($Level -eq [ORCAConfigLevel]::Informational -and $this.Level -eq [ORCAConfigLevel]::None))
        {
            $this.Level = $Level
        }

    }

    $Check
    $Object
    $ConfigItem
    $ConfigData
    $ConfigReadonly
    $ConfigDisabled
    [string]$ConfigPolicyGuid
    $InfoText
    [array]$Results
    [ORCAConfigLevel]$Level
}

Class ORCACheckConfigResult
{
    [ORCAConfigLevel]$Level=[ORCAConfigLevel]::Standard
    $Value
}

Class ORCACheck
{
    <#

        Check definition

        The checks defined below allow contextual information to be added in to the report HTML document.
        - Control               : A unique identifier that can be used to index the results back to the check
        - Area                  : The area that this check should appear within the report
        - PassText              : The text that should appear in the report when this 'control' passes
        - FailRecommendation    : The text that appears as a title when the 'control' fails. Short, descriptive. E.g "Do this"
        - Importance            : Why this is important
        - ExpandResults         : If we should create a table in the callout which points out which items fail and where
        - ObjectType            : When ExpandResults is set to, For Object, Property Value checks - what is the name of the Object, e.g a Spam Policy
        - ItemName              : When ExpandResults is set to, what does the check return as ConfigItem, for instance, is it a Transport Rule?
        - DataType              : When ExpandResults is set to, what type of data is returned in ConfigData, for instance, is it a Domain?    

    #>

    [Array] $Config=@()
    [string] $Control
    [String] $Area
    [String] $Name
    [String] $PassText
    [String] $FailRecommendation
    [Boolean] $ExpandResults=$false
    [String] $ObjectType
    [String] $ItemName
    [String] $DataType
    [String] $Importance
    [ORCACHI] $ChiValue = [ORCACHI]::NotRated
    [ORCAService]$Services = [ORCAService]::EOP
    [CheckType] $CheckType = [CheckType]::PropertyValue
    $Links
    $ORCAParams
    [Boolean] $SkipInReport=$false

    [ORCAResult] $Result=[ORCAResult]::Pass
    [int] $FailCount=0
    [int] $PassCount=0
    [int] $InfoCount=0
    [Boolean] $Completed=$false

    [Boolean] $CheckFailed = $false
    [String] $CheckFailureReason = $null
    
    # Overridden by check
    GetResults($Config) { }

    AddConfig([ORCACheckConfig]$Config)
    {

        # Manipulate result for disabled

        if($Config.ConfigDisabled -eq $True)
        {
            $Config.InfoText = "The policy is not enabled and will not apply. The configuration for this policy is not set properly according to this check. It is being flagged incase of accidental enablement."

            ForEach($c in $Config.Results)
            {
                # Downgrade Fails to Informational
                if($c.Level -ne [ORCAConfigLevel]::Pass)
                {
                    $c.Level = [ORCAConfigLevel]::Informational
                }
            }
        }
        
        $this.Config += $Config

        $this.FailCount = @($this.Config | Where-Object {$_.Level -eq [ORCAConfigLevel]::None}).Count
        $this.PassCount = @($this.Config | Where-Object {$_.Level -eq [ORCAConfigLevel]::Standard -or $_.Level -eq [ORCAConfigLevel]::Strict}).Count
        $this.InfoCount = @($this.Config | Where-Object {$_.Level -eq [ORCAConfigLevel]::Informational}).Count

        $InfoCountDefault =  @($this.Config | Where-Object {$_.InfoText -imatch "This is a Built-In/Default policy managed by Microsoft"}).Count
        $InfoCountDisabled =  @($this.Config | Where-Object {$_.InfoText -imatch "The policy is not enabled and will not apply"}).Count

        If($this.FailCount -eq 0 -and $this.InfoCount -eq 0)
        {
            $this.Result = [ORCAResult]::Pass
        }
        elseif($this.FailCount -eq 0 -and $this.InfoCount -gt 0)
        {
            if(($this.InfoCount -eq ($InfoCountDefault + $InfoCountDisabled)) -and ($this.PassCount -gt 0))
            {
                $this.Result = [ORCAResult]::Pass
            }
            else
            {$this.Result = [ORCAResult]::Informational}
        }
        else 
        {
            $this.Result = [ORCAResult]::Fail    
        }

    }

    # Run
    Run($Config)
    {
        Write-Host "$(Get-Date) Analysis - $($this.Area) - $($this.Name)"
        
        $this.GetResults($Config)

        If($this.SkipInReport -eq $True)
        {
            Write-Host "$(Get-Date) Skipping - $($this.Name) - No longer part of $($this.Area)"
            continue
        }

        # If there is no results to expand, turn off ExpandResults
        if($this.Config.Count -eq 0)
        {
            $this.ExpandResults = $false
        }

        # Set check module to completed
        $this.Completed=$true
    }

}

Class ORCAOutput
{

    [String]    $Name
    [Boolean]   $ShowSurvey             =   $true
    [Boolean]   $Completed              =   $False
                $VersionCheck           =   $null
                $DefaultOutputDirectory
                $Result

    # Function overridden
    RunOutput($Checks,$Collection)
    {

    }

    Run($Checks,$Collection)
    {
        Write-Host "$(Get-Date) Output - $($this.Name)"

        $this.RunOutput($Checks,$Collection)

        $this.Completed=$True
    }

}

Function Get-ORCACheckDefs
{
    Param
    (
        $ORCAParams
    )

    $Checks = @()

    # Load individual check definitions
    $CheckFiles = Get-ChildItem "$PSScriptRoot\Checks"

    ForEach($CheckFile in $CheckFiles)
    {
        if($CheckFile.BaseName -match '^check-(.*)$')
        {
            Write-Verbose "Importing $($matches[1])"
            . $CheckFile.FullName
            $Check = New-Object -TypeName $matches[1]

            # Set the ORCAParams
            $Check.ORCAParams = $ORCAParams

            $Checks += $Check
        }
    }

    Return $Checks
}

Function Get-ORCAOutputs
{
    Param
    (
        $VersionCheck,
        $Modules,
        $Options,
        $ShowSurvey
    )

    $Outputs = @()

    # Load individual check definitions
    $OutputFiles = Get-ChildItem "$PSScriptRoot\Outputs"

    ForEach($OutputFile in $OutputFiles)
    {
        if($OutputFile.BaseName -match '^output-(.*)$')
        {
            # Determine if this type should be loaded
            If($Modules -contains $matches[1])
            {
                Write-Verbose "Importing $($matches[1])"
                . $OutputFile.FullName
                $Output = New-Object -TypeName $matches[1]

                # Load any of the options in to the module
                If($Options)
                {

                If($Options[$matches[1]].Keys)
                {
                    ForEach($Opt in $Options[$matches[1]].Keys)
                    {
                        # Ensure this property exists before we try set it and get a null ref error
                        $ModProperties = $($Output | Get-Member | Where-Object {$_.MemberType -eq "Property"}).Name
    
                        If($ModProperties -contains $Opt)
                        {
                            $Output.$Opt = $Options[$matches[1]][$Opt]
                        }
                        else
                        {
                            Throw("There is no option $($Opt) on output module $($matches[1])")
                        }
                    }
                }
            }

                # For default output directory
                $Output.DefaultOutputDirectory = Get-ORCADirectory

                # Provide versioncheck
                $Output.VersionCheck = $VersionCheck
                $Output.ShowSurvey = $ShowSurvey
                
                $Outputs += $Output
            }

        }
    }

    Return $Outputs
}
Class PolicyStats
{
    [String]    $PolicyName
    [Boolean]   $IsEnabled    
}

Function Get-ORCACollection
{
    $Collection = @{}

    [ORCAService]$Collection["Services"] = [ORCAService]::EOP

    # Determine if ATP is available by checking for presence of an ATP command
    if($(Get-command Get-AtpPolicyForO365 -ErrorAction:SilentlyContinue))
    {
        $Collection["Services"] += [ORCAService]::OATP
    } 

    If(!$Collection["Services"] -band [ORCAService]::OATP)
    {
        Write-Host "$(Get-Date) Microsoft Defender for Office 365 is not detected - these checks will be skipped!" -ForegroundColor Red
    }

    Write-Host "$(Get-Date) Getting Anti-Spam Settings"
    $Collection["HostedConnectionFilterPolicy"] = Get-HostedConnectionFilterPolicy
    $Collection["HostedContentFilterPolicy"] = Get-HostedContentFilterPolicy
    $Collection["HostedContentFilterRule"] = Get-HostedContentFilterRule
    $Collection["HostedOutboundSpamFilterPolicy"] = Get-HostedOutboundSpamFilterPolicy
    $Collection["HostedOutboundSpamFilterRule"] = Get-HostedOutboundSpamFilterRule

    Write-Host "$(Get-Date) Getting Tenant Settings"
    $Collection["AdminAuditLogConfig"] = Get-AdminAuditLogConfig

    If($Collection["Services"] -band [ORCAService]::OATP)
    {
        Write-Host "$(Get-Date) Getting ATP Preset Policy Settings"
        $Collection["ATPProtectionPolicyRule"] = Get-ATPProtectionPolicyRule
        $Collection["ATPBuiltInProtectionRule"] = Get-ATPBuiltInProtectionRule
    }

    Write-Host "$(Get-Date) Getting EOP Preset Policy Settings"
    $Collection["EOPProtectionPolicyRule"] = Get-EOPProtectionPolicyRule

    Write-Host "$(Get-Date) Getting Quarantine Policy Settings"
    $Collection["QuarantineTag"] =  Get-QuarantinePolicy
    $Collection["QuarantineTagGlobal"]  = Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy

    If($Collection["Services"] -band [ORCAService]::OATP)
    {
        Write-Host "$(Get-Date) Getting Anti Phish Settings"
        $Collection["AntiPhishPolicy"] = Get-AntiphishPolicy
        $Collection["AntiPhishRules"] = Get-AntiPhishRule
    }

    Write-Host "$(Get-Date) Getting Anti-Malware Settings"
    $Collection["MalwareFilterPolicy"] = Get-MalwareFilterPolicy
    $Collection["MalwareFilterRule"] = Get-MalwareFilterRule

    Write-Host "$(Get-Date) Getting Transport Rules"
    $Collection["TransportRules"] = Get-TransportRule

    If($Collection["Services"] -band [ORCAService]::OATP)
    {
        Write-Host "$(Get-Date) Getting ATP Policies"
        $Collection["SafeAttachmentsPolicy"] = Get-SafeAttachmentPolicy
        $Collection["SafeAttachmentsRules"] = Get-SafeAttachmentRule
        $Collection["SafeLinksPolicy"] = Get-SafeLinksPolicy
        $Collection["SafeLinksRules"] = Get-SafeLinksRule
        $Collection["AtpPolicy"] = Get-AtpPolicyForO365
    }

    Write-Host "$(Get-Date) Getting Accepted Domains"
    $Collection["AcceptedDomains"] = Get-AcceptedDomain

    Write-Host "$(Get-Date) Getting DKIM Configuration"
    $Collection["DkimSigningConfig"] = Get-DkimSigningConfig

    Write-Host "$(Get-Date) Getting Connectors"
    $Collection["InboundConnector"] = Get-InboundConnector

    Write-Host "$(Get-Date) Getting Outlook External Settings"
    $Collection["ExternalInOutlook"] = Get-ExternalInOutlook

    # Required for Enhanced Filtering checks
    Write-Host "$(Get-Date) Getting MX Reports for all domains"
    $Collection["MXReports"] = @()
    ForEach($d in $Collection["AcceptedDomains"])
    {
        Try
        {
            $Collection["MXReports"] += Get-MxRecordReport -Domain $($d.DomainName) -ErrorAction:SilentlyContinue
        }
        Catch
        {
            Write-Verbose "$(Get-Date) Failed to get MX report for domain $($d.DomainName)"
        }
        
    }

    # Determine policy states
    Write-Host "$(Get-Date) Determining applied policy states"

    $Collection["PolicyStates"] = Get-PolicyStates -AntiphishPolicies $Collection["AntiPhishPolicy"] -AntiphishRules $Collection["AntiPhishRules"] -AntimalwarePolicies $Collection["MalwareFilterPolicy"] -AntimalwareRules $Collection["MalwareFilterRule"] -AntispamPolicies $Collection["HostedContentFilterPolicy"] -AntispamRules $Collection["HostedContentFilterRule"] -SafeLinksPolicies $Collection["SafeLinksPolicy"] -SafeLinksRules $Collection["SafeLinksRules"] -SafeAttachmentsPolicies $Collection["SafeAttachmentsPolicy"] -SafeAttachmentRules $Collection["SafeAttachmentsRules"] -ProtectionPolicyRulesATP $Collection["ATPProtectionPolicyRule"] -ProtectionPolicyRulesEOP $Collection["EOPProtectionPolicyRule"] -OutboundSpamPolicies $Collection["HostedOutboundSpamFilterPolicy"] -OutboundSpamRules $Collection["HostedOutboundSpamFilterRule"] -BuiltInProtectionRule $Collection["ATPBuiltInProtectionRule"]
    $Collection["AnyPolicyState"] = Get-AnyPolicyState -PolicyStates $Collection["PolicyStates"]

    # Add IsPreset properties for Preset policies (where applicable)
    Add-IsPresetValue -CollectionEntity $Collection["HostedContentFilterPolicy"]
    Add-IsPresetValue -CollectionEntity $Collection["EOPProtectionPolicyRule"]

    If($Collection["Services"] -band [ORCAService]::OATP)
    {
        Add-IsPresetValue -CollectionEntity $Collection["ATPProtectionPolicyRule"]
        Add-IsPresetValue -CollectionEntity $Collection["AntiPhishPolicy"]
        Add-IsPresetValue -CollectionEntity $Collection["SafeAttachmentsPolicy"]
        Add-IsPresetValue -CollectionEntity $Collection["SafeLinksPolicy"] 
    }

    Return $Collection
}

Function Add-IsPresetValue
{
    Param (
        $CollectionEntity
    )

    # List of preset names
    $PresetNames = @("Standard Preset Security Policy","Strict Preset Security Policy","Built-In Protection Policy")

    foreach($item in $CollectionEntity)
    {
        
        if($null -ne $item.Name)
        {
            $IsPreset = $PresetNames -contains $item.Name

            $item | Add-Member -MemberType NoteProperty -Name IsPreset -Value $IsPreset
        }
        
    }
}

Function Get-ORCAReport
{

    <#
    
        .SYNOPSIS
            The Office 365 Recommended Configuration Analyzer (ORCA)

        .DESCRIPTION
            Office 365 Recommended Configuration Analyzer (ORCA)

            The Get-ORCAReport command generates a HTML report based on the Microsoft Defender for Office 365 recommended practices article:
            https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp

            Output report uses open source components for HTML formatting:
            - Bootstrap - MIT License https://getbootstrap.com/docs/4.0/about/license/
            - Fontawesome - CC BY 4.0 License - https://fontawesome.com/license/free

        .PARAMETER NoConnect
            Prevents ORCA from connecting automatically to Exchange Online. In most circumstances you will not want to do this, we will
            detect if you're connected or not connected as part of running ORCA. Connection will only occur if we detect you are not
            connected.
        
        .PARAMETER NoVersionCheck
            Prevents ORCA from determining if it's running the latest version. It's always very important to be running the latest
            version of ORCA. We will change guidelines as the product and the recommended practices article changes. Not running the
            latest version might provide recommendations that are no longer valid.

        .PARAMETER AlternateDNS
            Will perform DNS checks using an alternate DNS server. This is really important if your organisation uses split DNS. Checks
            for your DKIM deployment for instance might fail if your DNS resolver is resolving your domains to the internal zone. This is
            because your internal zone doesn't require to have the DKIM selector records published. In these instances use the AlternateDNS
            flag to use different resolvers (ones that will provide the external DNS records for your domains).

        .PARAMETER DelegatedOrganization
            Passes the DelegatedOrganization when connecting to Exchange Online. The DelegatedOrganization parameter specifies the customer organization 
            that you want to manage (for example, contosoelectronics.onmicrosoft.com). 

            Only use this param when connecting to organizations that you have access to.

        .PARAMETER  ExchangeEnvironmentName
        This will generate MCCA report for Security & Compliance Center PowerShell in a Microsoft 365 DoD organization or Microsoft GCC High organization
         O365USGovDoD
           This will generate MCCA report for Security & Compliance Center PowerShell in a Microsoft 365 DoD organization.
         O365USGovGCCHigh
           This will generate MCCA report for Security & Compliance Center PowerShell in a Microsoft GCC High organization.

        .PARAMETER NoSurvey
            We need your input in to ORCA, but we appreciate that you may not have the time or desire to provide it. We've added this flag in here so that you
            can suppress survey prompts (please fill out the survey though!).

        .PARAMETER Collection
            Internal only.

        .EXAMPLE
            Get-ORCAReport

        .EXAMPLE
            Get-ORCAReport -AlternateDNS @("10.20.30.40","40.20.30.10")

    
    #>

    Param(
        [CmdletBinding()]
        [Switch]$NoConnect,
        [Switch]$NoVersionCheck,
        [Switch]$NoSurvey,
        [String[]]$AlternateDNS,
        [String]$DelegatedOrganization=$null,
        [string][validateset('O365Default', 'O365USGovDoD', 'O365USGovGCCHigh','O365GermanyCloud','O365China')] $ExchangeEnvironmentName = 'O365Default',
        $Collection
    )

    try { $statusCode = wget https://aka.ms/orca-execution -Method head | % { $_.StatusCode } }catch {}

    # Easy to use for quick ORCA report to HTML
    If($NoVersionCheck)
    {
        $PerformVersionCheck = $False
    }
    Else
    {
        $PerformVersionCheck = $True
    }

    if($NoSurvey)
    {
        $ShowSurvey = $False
    } else {
        $ShowSurvey = $True
    }

    $Connect = $False

    if(!$NoConnect)
    {
        # Determine if to connect

        if($(Get-EXConnectionStatus) -eq $False)
        {
            $Connect = $True
        } else {
            # Check delegated organization specified, and we are connected to this organization.

            if(![string]::IsNullOrEmpty($DelegatedOrganization))
            {
                $OrgID = (Get-OrganizationConfig).Identity

                if($OrgID -ne $DelegatedOrganization)
                {
                    Write-Host "Connected to $($OrgID) not delegated organization $($DelegatedOrganization), reconnecting.."
                    Disconnect-ExchangeOnline -Confirm:$False
                    $Connect = $True
                }
            }
        }
    }

    $Result = Invoke-ORCA -Connect $Connect -PerformVersionCheck $PerformVersionCheck -AlternateDNS $AlternateDNS -Collection $Collection -ExchangeEnvironmentName $ExchangeEnvironmentName -Output @("HTML") -DelegatedOrganization $DelegatedOrganization -ShowSurvey $ShowSurvey
    Write-Host "$(Get-Date) Complete! Output is in $($Result.Result)"

    # Pre-requisite checks
    if(!(Get-Command Resolve-DnsName -ErrorAction:SilentlyContinue))
    {
        Write-Warning "Resolve-DnsName command does not exist on this ORCA computer. On non windows machines, this command may not exist. Commands requiring DNS checks such as DKIM and SPF have failed! Follow instructions specific for your Operating System."
    }
}

class PolicyInfo {
    # Policy applies to something, is enabled, has a rule
    [bool] $Applies

    # Preset policy (Standard or Strict)
    [bool] $Preset

    # Preset level if applicable
    [PresetPolicyLevel] $PresetLevel

    # Built in policy (BIP)
    [bool] $BuiltIn

    # Default policy
    [bool] $Default
    [String] $Name
    [PolicyType] $Type
}

Function Get-PolicyStateInt
{
    <#
    .SYNOPSIS
        Called by Get-PolicyStates to process a policy
    #>

    Param(
        $Policies,
        $Rules,
        $ProtectionPolicyRules,
        $BuiltInProtectionRule,
        [PolicyType]$Type
    )

    $ReturnPolicies = @{}

    foreach($Policy in $Policies)
    {

        $Applies = $false
        $Default = $false
        $Preset = $false
        $PresetPolicyLevel = [PresetPolicyLevel]::None
        $BuiltIn = ($Policy.Identity -eq $BuiltInProtectionRule.SafeAttachmentPolicy -or $Policy.Identity -eq $BuiltInProtectionRule.SafeLinksPolicy)
        $Name = $Policy.Name

        # Determine preset - MDO
        if($Type -eq [PolicyType]::SafeLinks -or $Type -eq [PolicyType]::SafeAttachments)
        {
            $MatchingPolicyRule = @($ProtectionPolicyRules | Where-Object {$_.SafeAttachmentsPolicy -eq $Policy.Identity -or $_.SafeLinksPolicy -eq $Policy.Identity})
            
            if($MatchingPolicyRule.Count -gt 0)
            {
                $Preset = $True
                $Name = $MatchingPolicyRule[0].Name
            }
        }

        # Determine preset - EOP
        if($Type -eq [PolicyType]::Antiphish -or $Type -eq [PolicyType]::Spam -or $Type -eq [PolicyType]::Malware)
        {
            $MatchingPolicyRule = @($ProtectionPolicyRules | Where-Object {
                $_.HostedContentFilterPolicy -eq $Policy.Identity -or 
                $_.AntiPhishPolicy -eq $Policy.Identity -or
                $_.MalwareFilterPolicy -eq $Policy.Identity
            })
            
            if($MatchingPolicyRule.Count -gt 0)
            {
                $Preset = $True
                $Name = $MatchingPolicyRule[0].Name
            }
        }

        # Determine level of preset based on name
        if($Preset)
        {
            if($Name -like "Standard*")
            {
                $PresetPolicyLevel = ([PresetPolicyLevel]::Standard)
            }
            if($Name -like "Strict*")
            {
                $PresetPolicyLevel = ([PresetPolicyLevel]::Strict)
            }
        }

        # Built in rules always apply
        if($BuiltIn)
        {
            $Applies = $True
        }

        # Checks for default policies EOP
        if(
            $Policy.DistinguishedName.StartsWith("CN=Default,CN=Malware Filter,CN=Transport Settings") -or 
            $Policy.DistinguishedName.StartsWith("CN=Default,CN=Hosted Content Filter,CN=Transport Settings") -or
            $Policy.DistinguishedName.StartsWith("CN=Default,CN=Outbound Spam Filter,CN=Transport Settings"))
        {
            $Default = $True
            $Applies = $True
        }

        # Check for default policies MDO
        if ($Policy.DistinguishedName.StartsWith("CN=Office365 AntiPhish Default,CN=AntiPhish,CN=Transport Settings,CN=Configuration"))
        {
            $Default = $True
            
            # Policy will apply based on Enabled state
            $Applies = $Policy.Enabled
        }

        # If not applying - check rules for application
        if(!$Applies)
        {

            # If Preset, rules to check is the protection policy rules (ATP or EOP protection policy rules), if not, the policy rules.
            if($Preset)
            {
                $CheckRules = $ProtectionPolicyRules
            } else {
                $CheckRules = $Rules
            }

            foreach($Rule in $($CheckRules | Where-Object {$_.Name -eq $Policy.Name}))
            {
                if($Rule.State -eq "Enabled")
                {
                    if($Rule.SentTo.Count -gt 0 -or $Rule.SentToMemberOf.Count -gt 0 -or $Rule.RecipientDomainIs.Count -gt 0)
                    {
                        $Applies = $true
                    }

                    # Outbound spam uses From, FromMemberOf and SenderDomainIs conditions
                    if($Type -eq [PolicyType]::OutboundSpam)
                    {
                        if($Rule.From.Count -gt 0 -or $Rule.FromMemberOf.Count -gt 0 -or $Rule.SenderDomainIs.Count -gt 0)
                        {
                            $Applies = $true
                        }
                    }
                }
            }
        }

        $ReturnPolicies[$Policy.Guid.ToString()] = New-Object -TypeName PolicyInfo -Property @{
            Applies=$Applies
            Preset=$Preset
            PresetLevel=($PresetPolicyLevel)
            BuiltIn=$BuiltIn
            Default=$Default
            Name=$Name 
            Type=$Type
        }
    }

    return $ReturnPolicies
}

Function Get-PolicyStates
{
    <#
    .SYNOPSIS
        Returns hashtable of all policy GUIDs and if they are applied
    #>

    Param(
        $AntiphishPolicies,
        $AntiphishRules,
        $AntimalwarePolicies,
        $AntimalwareRules,
        $AntispamPolicies,
        $AntispamRules,
        $OutboundSpamPolicies,
        $OutboundSpamRules,
        $SafeLinksPolicies,
        $SafeLinksRules,
        $SafeAttachmentsPolicies,
        $SafeAttachmentRules,
        $ProtectionPolicyRulesATP,
        $ProtectionPolicyRulesEOP,
        $BuiltInProtectionRule
    )

    $ReturnPolicies = @{}

    $ReturnPolicies += Get-PolicyStateInt -Policies $AntiphishPolicies -Rules $AntiphishRules -Type ([PolicyType]::Antiphish) -ProtectionPolicyRules $ProtectionPolicyRulesEOP -BuiltInProtectionRule $BuiltInProtectionRule
    $ReturnPolicies += Get-PolicyStateInt -Policies $AntimalwarePolicies -Rules $AntimalwareRules -Type ([PolicyType]::Malware) -ProtectionPolicyRules $ProtectionPolicyRulesEOP
    $ReturnPolicies += Get-PolicyStateInt -Policies $AntispamPolicies -Rules $AntispamRules -Type ([PolicyType]::Spam) -ProtectionPolicyRules $ProtectionPolicyRulesEOP
    $ReturnPolicies += Get-PolicyStateInt -Policies $SafeLinksPolicies -Rules $SafeLinksRules -Type ([PolicyType]::SafeAttachments) -ProtectionPolicyRules $ProtectionPolicyRulesATP -BuiltInProtectionRule $BuiltInProtectionRule
    $ReturnPolicies += Get-PolicyStateInt -Policies $SafeAttachmentsPolicies -Rules $SafeAttachmentRules -Type ([PolicyType]::SafeLinks) -ProtectionPolicyRules $ProtectionPolicyRulesATP -BuiltInProtectionRule $BuiltInProtectionRule
    $ReturnPolicies += Get-PolicyStateInt -Policies $OutboundSpamPolicies -Rules $OutboundSpamRules -Type ([PolicyType]::OutboundSpam) -ProtectionPolicyRules $ProtectionPolicyRulesATP -BuiltInProtectionRule $BuiltInProtectionRule

    return $ReturnPolicies
}

function Get-AnyPolicyState
{
    <#
    .SYNOPSIS
        Returns if any policy is enabled and applies
    #>

    Param(
        $PolicyStates
    )

    $ReturnVals = @{}
    $ReturnVals[[PolicyType]::Antiphish] = $False
    $ReturnVals[[PolicyType]::Malware] = $False
    $ReturnVals[[PolicyType]::Spam] = $False
    $ReturnVals[[PolicyType]::SafeAttachments] = $False
    $ReturnVals[[PolicyType]::SafeLinks] = $False

    foreach($Key in $PolicyStates.Keys)
    {

        if($PolicyStates[$Key].Type -eq [PolicyType]::Antiphish -and $PolicyStates[$Key].Applies)
        {
            $ReturnVals[[PolicyType]::Antiphish] = $True
        }

        if($PolicyStates[$Key].Type -eq [PolicyType]::Malware -and $PolicyStates[$Key].Applies)
        {
            $ReturnVals[[PolicyType]::Malware] = $True
        }

        if($PolicyStates[$Key].Type -eq [PolicyType]::Spam -and $PolicyStates[$Key].Applies)
        {
            $ReturnVals[[PolicyType]::Spam] = $True
        }

        if($PolicyStates[$Key].Type -eq [PolicyType]::SafeAttachments -and $PolicyStates[$Key].Applies)
        {
            $ReturnVals[[PolicyType]::SafeAttachments] = $True
        }

        if($PolicyStates[$Key].Type -eq [PolicyType]::SafeLinks -and $PolicyStates[$Key].Applies)
        {
            $ReturnVals[[PolicyType]::SafeLinks]  = $True
        }
    }

    return $ReturnVals;

}

Function Invoke-ORCA
{

    <#
    
        .SYNOPSIS
            The Office 365 Recommended Configuration Analyzer (ORCA)

        .DESCRIPTION
            Office 365 Recommended Configuration Analyzer (ORCA)

            Unless you are wanting to automate ORCA, do not use Invoke-ORCA, run Get-ORCAReport instead!!

            The Invoke-ORCA command allows you to output different formats based on the Microsoft Defender for Office 365 recommended practices article:
            https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp

            HTML Output report uses open source components for HTML formatting:
            - Bootstrap - MIT License https://getbootstrap.com/docs/4.0/about/license/
            - Fontawesome - CC BY 4.0 License - https://fontawesome.com/license/free

        .PARAMETER Output
            Array of output modules you would like to invoke. You can specify multiple different outputs. Outputs are modular, and
            additional outputs can be written and placed in the modules Outputs directory if required.

            Out of the box, the following outputs are included
            - HTML
            - JSON (File)
            - Cosmos DB (Requires CosmosDB third-party module)

            As this is an array, you can specify different outputs
            
            -Output "HTML"
                Will output just HTML
            -Output @("HTML","JSON")
                Will output the HTML report and the JSON report
        
        .PARAMETER OutputOptions
            Array of options for the output modules.

            Example if running a Cosmos output, you'll need to tell it which account, database and key to use like this:

            -OutputOptions @{Cosmos=@{Account='MyCosmosAccount';Database='MyCosmosDB';Key='<Your key>';Collection='MyORCA'}}

            If you're running multiple different outputs, just use a different key for that output module, for instance this will provide the Cosmos details to the Cosmos module
            and HTML details to the HTML module.

            -OutputOptions @{HTML=@{DisplayReport=$False};Cosmos=@{Account='MyCosmosAccount';Database='MyCosmosDB';Key='<Your key>';Collection='MyORCA'}}
        
        .PARAMETER PerformVersionCheck
            Prevents ORCA from determining if it's running the latest version if set to $False. It's always very important to be running the latest
            version of ORCA. We will change guidelines as the product and the recommended practices article changes. Not running the
            latest version might provide recommendations that are no longer valid.

        .PARAMETER Connect
            Prevents ORCA from connecting automatically to Exchange Online if set to $False. In most circumstances you will not want to do this, we will
            detect if you're connected or not connected as part of running ORCA. Connection will only occur if we detect you are not
            connected.

        .PARAMETER AlternateDNS
            Will perform DNS checks using an alternate DNS server. This is really important if your organisation uses split DNS. Checks
            for your DKIM deployment for instance might fail if your DNS resolver is resolving your domains to the internal zone. This is
            because your internal zone doesn't require to have the DKIM selector records published. In these instances use the AlternateDNS
            flag to use different resolvers (ones that will provide the external DNS records for your domains).

        .PARAMETER InstallModules
            Attempts to install missing modules (such as Exchange Online Management) in to the CurrentUser scope if they are missing. Defaults to $True

        .PARAMETER DelegatedOrganization
            Passes the DelegatedOrganization when connecting to Exchange Online. The DelegatedOrganization parameter specifies the customer organization 
            that you want to manage (for example, contosoelectronics.onmicrosoft.com). 

            Only use this param when connecting to organizations that you have access to.

        .PARAMETER Collection
            Internal only.

        .EXAMPLE
            Invoke-ORCA -Output "HTML"

        .EXAMPLE
            Invoke-ORCA -Output @("HTML","JSON")

        .EXAMPLE
            Invoke-ORCA -Output @("HTML","JSON") -OutputOptions @{HTML=@{DisplayReport=$False}}

        .EXAMPLE
            Invoke-ORCA -Output "COSMOS" -OutputOptions @{HTML=@{DisplayReport=$False};Cosmos=@{Account='MyCosmosAccount';Database='MyCosmosDB';Key='YourKeyvalue';Collection='MyORCA'}}

    
    #>

    Param(
        [CmdletBinding()]
        [Boolean]$Connect=$True,
        [Boolean]$PerformVersionCheck=$True,
        [Boolean]$InstallModules=$True,
        [Boolean]$ShowSurvey=$True,
        [String[]]$AlternateDNS,
        [String]$DelegatedOrganization=$null,
        [string][validateset('O365Default', 'O365USGovDoD', 'O365USGovGCCHigh')] $ExchangeEnvironmentName,
        $Output,
        $OutputOptions,
        $Collection
    )

    # Version check
    $VersionCheck = Invoke-ORCAVersionCheck -GalleryCheck $PerformVersionCheck

    If($Connect)
    {
        Invoke-ORCAConnections  -ExchangeEnvironmentName $ExchangeEnvironmentName -Install $InstallModules -DelegatedOrganization $DelegatedOrganization
    }

    # Build a param object which can be used to pass params to the underlying classes
    $ORCAParams = New-Object -TypeName PSObject -Property @{
        AlternateDNS=$AlternateDNS
    }

    # Get the output modules
    $OutputModules = Get-ORCAOutputs -VersionCheck $VersionCheck -Modules $Output -Options $OutputOptions -ShowSurvey $ShowSurvey

    # Get the object of ORCA checks
    $Checks = Get-ORCACheckDefs -ORCAParams $ORCAParams

    # Get the collection in to memory. For testing purposes, we support passing the collection as an object
    If($Null -eq $Collection)
    {
        $Collection = Get-ORCACollection
    }

    # Perform checks inside classes/modules
    ForEach($Check in ($Checks | Sort-Object Area))
    {

        # Run EOP checks by default
        if($check.Services -band [ORCAService]::EOP)
        {
            $Check.Run($Collection)
        }

        # Run ATP checks only when ATP is present
        if($check.Services -band [ORCAService]::OATP -and $Collection["Services"] -band [ORCAService]::OATP)
        {
            $Check.Run($Collection)
        }
    }

    # Manipulation of check results for disable/read-only


    <#
    
        The Configuration Health Index

        Each configuration has a score, the CHISum below is a summary of the score based on each check.
        To gain the points in the score, the check must pass or be informational, fail checks do not count.

        The Configuration Health Index is the percentage of CHISum and the total points that are available.
    
    #>

    # Generate the CHI value
    $CHITotal = 0
    $CHISum = 0

    ForEach($Check in ($Checks))
    {
        $CHITotal += $($Check.Config.Count) * $($Check.ChiValue)
        $CHISum += $($Check.InfoCount + $Check.PassCount) * $($Check.ChiValue)
    }

    $CHI = [Math]::Round($($CHISum / $CHITotal) * 100)

    $Collection["CHI"] = $($CHI)

    $OutputResults = @()

    Write-Host "$(Get-Date) Generating Output" -ForegroundColor Green
    # Perform required outputs
    ForEach($o in $OutputModules)
    {

        $o.Run($Checks,$Collection)
        $OutputResults += New-Object -TypeName PSObject -Property @{
            Name=$o.name
            Completed=$o.completed
            Result=$o.Result
        }

    }

    CountORCAStat -Domains $Collection["AcceptedDomains"] -Version $VersionCheck.Version

    Return $OutputResults

}

function CountORCAStat
{
    Param (
        $Domains,
        $Version
    )

    try {
        $TenantDomain = ($Domains | Where-Object {$_.InitialDomain -eq $True}).DomainName
        $mystream = [IO.MemoryStream]::new([byte[]][char[]]$TenantDomain)
        $Hash = (Get-FileHash -InputStream $mystream -Algorithm SHA256).Hash
        $Obj = New-Object -TypeName PSObject -Property @{
            id=$Hash
            Version=$Version
        }
        Invoke-RestMethod -Method POST -Uri "https://orcastat.azurewebsites.net/stat" -Body (ConvertTo-Json $Obj) -ContentType "application/json" | Out-Null
    }
    catch {
        <#Do this if a terminating exception happens#>
    }


}


function Invoke-ORCAVersionCheck
{
    Param
    (
        $Terminate,
        [Boolean] $GalleryCheck
    )

    Write-Host "$(Get-Date) Performing ORCA Version check..."

    # When detected we are running the preview release
    $Preview = $False

    try 
    {
        $ORCAVersion = (Get-Module ORCA | Sort-Object Version -Desc)[0].Version
    }
    catch 
    {
        $ORCAVersion = (Get-Module ORCAPreview | Sort-Object Version -Desc)[0].Version

        if($ORCAVersion)
        {
            $Preview = $True
        }
    }

    if($GalleryCheck)
    {
        if($Preview -eq $False)
        {
            $PSGalleryVersion = (Find-Module ORCA -Repository PSGallery -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue).Version
        }
        else 
        {
            $PSGalleryVersion = (Find-Module ORCAPreview -Repository PSGallery -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue).Version
        }
        
    
        If($PSGalleryVersion -gt $ORCAVersion)
        {
            $Updated = $False
            If($Terminate)
            {
                Throw "ORCA is out of date. Your version is $ORCAVersion and the published version is $PSGalleryVersion. Run Update-Module ORCA or run with -NoUpdate."
            }
            else {
                Write-Host "$(Get-Date) ORCA is out of date. Your version: $($ORCAVersion) published version is $($PSGalleryVersion)"
            }
        }
        else
        {
            $Updated = $True
        }
    }

    Return New-Object -TypeName PSObject -Property @{
        Updated=$Updated
        Version=$ORCAVersion
        GalleryCheck=$GalleryCheck
        GalleryVersion=$PSGalleryVersion
        Preview=$Preview
    }
}

function Get-EXConnectionStatus
{
    # Perform check to determine if we are connected
    Try
    {
        Get-HostedConnectionFilterPolicy -WarningAction:SilentlyContinue | Out-Null
        Return $True
    }
    Catch
    {
        Return $False
    }
}
