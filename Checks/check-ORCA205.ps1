<#

205 Checks to determine if Common attachment type filter is enbaled in EOP Anti-malware policy.

#>

using module "..\ORCA.psm1"

class ORCA205 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA205()
    {
        $this.Control=205
        $this.Area="Malware Filter Policy"
        $this.Name="Common Attachment Type Filter"
        $this.PassText="Common attachment type filter is enabled"
        $this.FailRecommendation="Enable common attachment type filter"
        $this.Importance="The common attachment type filter can block file types that commonly contain malware, including in internal emails."
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.Links= @{
            "Configure anti-malware policies"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-anti-malware-policies"
            "Recommended settings for EOP and Office 365 ATP security"="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365-atp#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in $Config["MalwareFilterPolicy"])
        {

            # Fail if EnableFileFilter is not set to true or FileTypes is empty in the policy

            If($Policy.EnableFileFilter -eq $false) 
            {
                $EnableFileFilter_Result = "Fail"
            }
            Else
            {
                $EnableFileFilter_Result = "Pass"
            }

            If(@($Policy.FileTypes).Count -eq 0) 
            {
                $Filetypes_Result = "Fail"
            }
            Else
            {
                $Filetypes_Result = "Pass"
            }

            $this.Results += New-Object -TypeName psobject -Property @{
                Result=$EnableFileFilter_Result
                Object=$($Policy.Name)
                ConfigItem="EnableFileFilter"
                ConfigData=$($Policy.EnableFileFilter)
                Control=$this.Control
            }
            
            $this.Results += New-Object -TypeName psobject -Property @{
                Result=$Filetypes_Result
                Object=$($Policy.Name)
                ConfigItem="FileTypes"
                ConfigData=$(@($Policy.FileTypes).Count)
                Control=$this.Control
            } 
        }
        
    }

}