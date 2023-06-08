using module "..\ORCA.psm1"

class cosmos : ORCAOutput
{

    $Account=$null
    $Database=$null
    $Key=$null
    $Collection="ORCA"
    $CosmosDBContext=$null

    cosmos()
    {
        $this.Name="Cosmos"
    }

    RunOutput($Checks,$Collection,[ORCAConfigLevel]$AssessmentLevel)
    {

        # Make sure that we have CosmosDB module

        If(!$(Get-Module -ListAvailable "CosmosDB" -ErrorAction:SilentlyContinue))
        {
            Throw "The Cosmos output requires the unofficial CosmosDB module to be installed. Run Install-Module CosmosDB."
        }

        # Check that the required params are set
        If($null -eq $this.Account -or $null -eq $this.Database -or $null -eq $this.key)
        {
            Throw "The Cosmos output requires the Account, Database, and Key options to be set. Review the documentation for more information."
        }

        # Check key type we got passed
        If($this.Key.GetType() -eq [String])
        {
            $this.Key = $(ConvertTo-SecureString -String $this.Key -AsPlainText -Force)
        }
        ElseIf($this.Key.GetType() -ne [SecureString])
        {
            Throw "The Cosmos option Key must either be a string or a secure string."
        }

        # Try set the Cosmos Database Context
        if($null -eq $this.CosmosDBContext)
        {
            try 
            {
                $this.CosmosDBContext = New-CosmosDbContext -Account $this.Account -Database $this.Database -Key $this.Key
            }
            catch 
            {
                Throw "Failed to set the Cosmos DB context. Ensure that the Account, Database, and Key are correct."
            }
        }

        $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
        $ID = "$($tenant)-$(Get-Date -Format 'yyyyMMddHHmmss')"

        $Result = New-Object -TypeName PSObject -Property @{
            id=$ID
            ResultDate=$(Get-Date -format s)
            Tenant=$Tenant
            Results=$Checks
        }

        $r = $null

        try 
        {
            $JSON = $($Result | ConvertTo-Json -Depth 100)
            $r = New-CosmosDbDocument -Context $this.CosmosDBContext -CollectionId $this.Collection -DocumentBody $JSON -PartitionKey $ID
            $this.Completed = $True
        }
        catch 
        {
            Throw "Failed to insert Cosmos DB document, check that all options are set correctly, there is a collection called $($this.Collection) with a partition key of id, and that you have connectivity to Cosmos"
        }

        $this.Result = $r

    }

}