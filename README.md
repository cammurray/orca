# ORCA
The Office 365 ATP Recommended Configuration Analyzer (ORCA).

## Introduction
ORCA is a report that you can run in your environment which can highlight known configuration issues and improvements which can impact your experience with Office 365 Advanced Threat Protection (ATP).

## What's in scope
* Configuration in EOP which can impact ATP
* SafeLinks configuration
* SafeAttachments configuration
* Antiphish and antispoof policies.

## Sounds good! How do I run it?

You will need the Exchange Online Management Shell first up, so get it at http://aka.ms/exopsmodule - we use this to connect to Exchange Online and look at your configuration.

Then, you'll need ORCA. We publish ORCA via the PowerShell gallery to make it easy and accessible for everyone.

To install, run PowerShell as an administrator and run the following command

`Install-Module ORCA`

Connect to Exchange Online and then run

`Get-ORCAReport`

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

### What if I don't have Advanced Threat Protection (ATP)?

There is definitely a lot of value in running your Office 365 environment with Advanced Threat Protection, for instance:
* Automatic incident response capabilities
* Attack simulation capabilities
* Behavioural analysis (sandboxing) of malware
* Time of click protection for malicious URLs
* Advanced anti-phishing controls

However, there are also some checks within ORCA that are non-ATP specific which can impact the operation of ATP and security within an Office 365 tenant. ORCA can still be ran on tenants with no ATP, albeit with reduced qty. of checks.
