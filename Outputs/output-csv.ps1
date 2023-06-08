using module "..\ORCA.psm1"

class csv : ORCAOutput
{

    $OutputDirectory=$null

    csv()
    {
        $this.Name="CSV"
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

        $ResultOverview = @()
        $ResultDetail = @()

        # Parse to flatten the output, for the overview some data is going to get lost because it's not a flat structure
        ForEach($c in $Checks)
        {

            $ResultOverview += New-Object -TypeName PSObject -Property @{
                Control=$c.Control
                Area=$c.Area
                Name=$c.Name
                Result=$($c.Result.ToString())
                AssessmentLevel=$($AssessmentLevel.ToString())
                ObjectsFailed=$c.GetCountAtLevelFail($AssessmentLevel)
                ObjectsPassed=$c.GetCountAtLevelPass($AssessmentLevel)
                ObjectsInfo=$c.GetCountAtLevelInfo($AssessmentLevel)
            }

            ForEach($config in $c.Config)
            {
                $ResultDetail += New-Object -TypeName PSObject -Property @{
                    Control=$c.Control
                    Area=$c.Area
                    Name=$c.Name
                    ConfigObject=$config.Object
                    ConfigItem=$config.ConfigItem
                    ConfigDisabled=$config.ConfigDisabled
                    ConfigReadonly=$config.ConfigReadonly
                    ConfigData=$config.ConfigData
                    ConfigPolicyGuid=$config.ConfigPolicyGuid
                    Level=$($config.Level.ToString())
                }
            }
        }

        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
        $ReportFileNameOverview = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').csv"
        $ReportFileNameDetail = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm')-Detail.csv"

        $OverviewFile = "$OutputDir\$ReportFileNameOverview"
        $DetailFile = "$OutputDir\$ReportFileNameDetail"

        $ResultOverview | Select-Object Control,Area,Name,AssessmentLevel,Result,ObjectsFailed,ObjectsPassed,ObjectsInfo | Export-Csv $OverviewFile -NoTypeInformation
        $ResultDetail | Select-Object Control,Area,Name,ConfigObject,ConfigItem,ConfigData,ConfigReadonly,ConfigDisabled,ConfigPolicyGuid,Level | Export-Csv $DetailFile -NoTypeInformation

        $this.Completed = $True
        $this.Result = New-Object -TypeName PSObject -Property @{
            Overview=$OverviewFile
            Detail=$DetailFile
        }

    }

}