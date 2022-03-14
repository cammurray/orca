# ORCA
The Microsoft Defender for Office 365 Recommended Configuration Analyzer (ORCA)

## Introduction
ORCA is a report that you can run in your environment which can highlight known configuration issues and improvements which can impact your experience with Microsoft Defender for Office 365 (formerly Office 365 Advanced Threat Protection).

## What's in scope
* Configuration Health Index
* Configuration in EOP which can impact ATP
* SafeLinks configuration
* SafeAttachments configuration
* Antiphish and antispoof policies.

## What is Configuration Health Index

The configuration health index is a weighted value representing your configuration. Not all configuration is considered and some configuration is weighted higher than others. The index is represented as a percentage. How the configuration impacts the configuration health index is shown next to the recommendation in the report below as a positive or negative number. The impact to your security posture is a large consideration factor when rating the configuration.


## Sounds good! How do I run it?

You will need the Exchange Online Management Shell first.

* Exchange Online PowerShell V2 module is availible via the PowerShell gallery:

 `Install-Module -Name ExchangeOnlineManagement`

**or** 

* Exchange Online PowerShell module http://aka.ms/exopsmodule 

We use these modules to connect to Exchange Online and look at your configuration.

Then, you'll need ORCA. We publish ORCA via the PowerShell gallery to make it easy and accessible for everyone.

To install, run PowerShell as an administrator and run the following command

`Install-Module ORCA`

Connect to Exchange Online and then run

`Get-ORCAReport`

To Run ORCA you need to have necessary permissions. 
The "View-Only Configuration" Exchange Online role is needed to run the tool.

For example you can use the following:
* Global Reader - Azure Active Directory role
* View-Only Organization Management - built in role group in Exchange Online

It's that simple! At the conclusion, your default browser will open with a report detailing the recommendations.

## What if I have issues?

Log an Issue via the Issues tab in GitHub!

# License

We're completely open source and as matter of fact we also use some open source components in our report.

We use the following components in order to generate the report
* Bootstrap, MIT License - https://getbootstrap.com/docs/4.0/about/license/
* Fontawesome, CC BY 4.0 License - https://fontawesome.com/license/free

# FAQ

### Is it kept up to date?

Yes! We will push new rule definitions out by releasing a new version. Every time you run Get-ORCAReport, we check to see if you have the latest version and if not; we will prompt you to update via the console and also in the report.

### What if I don't have Microsoft Defender for Office 365?

There is definitely a lot of value in running your Office 365 environment with Microsoft Defender for Office 365, for instance:
* Automatic incident response capabilities
* Attack simulation capabilities
* Behavioural analysis (sandboxing) of malware
* Time of click protection for malicious URLs
* Advanced anti-phishing controls

However, there are also some checks within ORCA that are not Microsoft Defender for Office 365 specific which can impact the operation of Microsoft Defender for Office 365 and security within an Office 365 tenant. ORCA can still be ran on tenants without Microsoft Defender for Office 365, albeit with reduced qty. of checks..

# Outputs

We now support outputting to different formats (which can be useful for different purposes, such as tracking trending over time).

If the following isn't good enough for your purpose, don't despair, the output is fully modular. You can create your own output type by creating your own "output-name.ps1" file in the outputs directory. You'll need to create a class that extends the "ORCAOutput" class, and you'll need to implement an override for the RunOutput function. Easiest way is just to copy one of the exsting ps1's to make your own (if you need to, that is..)

## Running specifying an alternative output

To run specifying an alternative output module, instead of using the Get-ORCAReport command, use the Invoke-ORCA command.

Example outputting to JSON

`Invoke-ORCA -Output JSON`

## Supported outputs

### HTML

HTML is the output format that you'll get when you run Get-ORCAReport.

Example 1 - this is the equivelant of running Get-ORCAReport:

`Invoke-ORCA -Output HTML`

Example 2 - output to HTML but don't load the HTML

`Invoke-ORCA -Output HTML -OutputOptions @{HTML=@{DisplayReport=$False}}`

#### Supported Params

* DisplayReport, Optional, Boolean - load the report at the conclusion of running ORCA
* OutputDirectory, Optional, String - path to store the outputted html file, default is an appdata directory created automatically

### JSON

File with JSON formatted results.

Example:

`Invoke-ORCA -Output JSON`

### CSV

Output flatted in to two CSV files, one for an overview, one for detail on each config item.

Example:

`Invoke-ORCA -Output CSV`

#### Supported Params

* OutputDirectory, Optional, String - path to store the outputted json file, default is an appdata directory created automatically

### CosmosDB

Useful for storing your results, trending, or displaying in a interface (PowerBI example coming soon)

We **require** the **unofficial** CosmosDB module 'CosmosDB' for this. You can find this on the PowerShell Gallery

The key that we will use is 'id' in the CosmosDB. Make sure you specify this as your key when you create your collection.

Example - To output in to MyCosmosAccount database MyCosmosDB, the default collection will be ORCA

`Invoke-ORCA -Output Cosmos -OutputOptions @{Cosmos=@{Account='MyCosmosAccount';Database='MyCosmosDB';Key='GFJqJesi2Rq910E0G7P4WoZkzowzbj23Sm9DUWFX0l0P8o16mYyuaZBN00Nbtj9F1QQnumzZKSGZwknXGERrlA=='}}`

Example - To output in to MyCosmosAccount database MyCosmosDB, in to a collection called MyORCA

`Invoke-ORCA -Output Cosmos -OutputOptions @{Cosmos=@{Account='MyCosmosAccount';Database='MyCosmosDB';Key='GFJqJesi2Rq910E0G7P4WoZkzowzbj23Sm9DUWFX0l0P8o16mYyuaZBN00Nbtj9F1QQnumzZKSGZwknXGERrlA==';Collection='MyORCA'}}`

#### Supported Params

* Account, Required, String - The Cosmos DB account that the database is found in
* Database, Required, String - The Cosmos DB name
* Key, Required, String - One of the keys for this Cosmos DB account
* Collection, Optional, String - The collection to output in to, by default this will be ORCA