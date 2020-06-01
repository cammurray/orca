using module "..\ORCA.psm1"

class csv : ORCAOutput
{

    $OutputDirectory=$null

    csv()
    {
        $this.Name="CSV"
    }

    RunOutput($Checks,$Collection)
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
                ObjectsFailed=$c.FailCount
                ObjectsPassed=$c.PassCount
                ObjectsInfo=$c.InfoCount
            }

            ForEach($config in $c.Config)
            {
                $ResultDetail += New-Object -TypeName PSObject -Property @{
                    Control=$c.Control
                    Area=$c.Area
                    Name=$c.Name
                    ConfigObject=$config.Object
                    ConfigItem=$config.ConfigItem
                    ConfigData=$config.ConfigData
                    Level=$($config.Level.ToString())
                }
            }
        }

        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
        $ReportFileNameOverview = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').csv"
        $ReportFileNameDetail = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm')-Detail.csv"

        $OverviewFile = "$OutputDir\$ReportFileNameOverview"
        $DetailFile = "$OutputDir\$ReportFileNameDetail"

        $ResultOverview | Select-Object Control,Area,Name,Result,ObjectsFailed,ObjectsPassed,ObjectsInfo,Text | Export-Csv $OverviewFile -NoTypeInformation
        $ResultDetail | Select-Object Control,Area,Name,ConfigObject,ConfigItem,ConfigData,Level | Export-Csv $DetailFile -NoTypeInformation

        $this.Completed = $True
        $this.Result = New-Object -TypeName PSObject -Property @{
            Overview=$OverviewFile
            Detail=$DetailFile
        }

    }

}