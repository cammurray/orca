using module "..\ORCA.psm1"

class config : ORCAOutput
{

    $OutputDirectory=$null

    json()
    {
        $this.Name="Config"
    }

    RunOutput($Checks,$Collection,[ORCAConfigLevel]$AssessmentLevel)
    {

        # Write to file

        if($null -eq $this.OutputDirectory)
        {
            $OutputDir = "$($this.DefaultOutputDirectory)\Config"
        }
        else 
        {
            $OutputDir = "$($this.OutputDirectory)\Config"
        }

        # Force create config dir
        New-Item -ItemType Directory -Force $OutputDir

        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
        $ReportFileName = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm')"

        $OutputFileJSON = "$($OutputDir)\$($ReportFileName).json"
        $OutputFileXML = "$($OutputDir)\$($ReportFileName).xml"

        # Pump out xml version
        $Collection | Export-CliXml  $OutputFileXML

        # Remove custom added collection components
        $Collection.Remove("PolicyStates")
        $Collection.Remove("AnyPolicyState")

        $Collection | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutputFileJSON

        $this.Completed = $True
        $this.Result = $OutputFileXML

    }

}