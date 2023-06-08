using module "..\ORCA.psm1"

class json : ORCAOutput
{

    $OutputDirectory=$null

    json()
    {
        $this.Name="JSON"
    }

    RunOutput($Checks,$Collection,[ORCAConfigLevel]$AssessmentLevel)
    {

        # Write to file

        if($null -eq $this.OutputDirectory)
        {
            $OutputDir = $this.DefaultOutputDirectory
        }
        else 
        {
            $OutputDir = $this.OutputDirectory
        }

        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
        $ReportFileName = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').json"

        $OutputFile = "$OutputDir\$ReportFileName"

        $Result = New-Object -TypeName PSObject -Property @{
            ResultDate=$(Get-Date -format s)
            Tenant=$Tenant
            Results=$Checks
        }

        $Result | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutputFile

        $this.Completed = $True
        $this.Result = $OutputFile

    }

}