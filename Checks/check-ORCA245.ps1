using module "..\ORCA.psm1"

class ORCA245 : ORCACheck
{
    <#
    
        Check for if a preset policy applies
    
    #>

    ORCA245()
    {
        $this.Control=245
        $this.Services=[ORCAService]::EOP
        $this.Area="Policy Baseline"
        $this.Name="Preset policies"
        $this.PassText="Preset policy is applied to each area without exceptions"
        $this.FailRecommendation="Configure a preset policy on each policy area without exceptions"
        $this.Importance="By applying a pre-set policy, you define a minimum bar for your security controls. As preset policies are assigned after custom policies, assigning a preset policy will still allow you to assign options for particular sets of users, whilst forming a minimum bar for users without specific custom policies assigned to them."
        $this.ExpandResults=$True
        $this.ItemName="Policy Area"
        $this.DataType="Preset policy applied"
        $this.ChiValue=[ORCACHI]::Medium
        $this.ObjectType="Policy"
        $this.Links= @{
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $MalwarePreset = $null;
        $AntiphishPreset = $null;
        $SpamPreset = $null;
        $SAPreset = $null;
        $SLPreset = $null;

        foreach($Key in $Config["PolicyStates"].Keys)
        {

            # Does the policy apply, and is it a preset

            if($Config["PolicyStates"][$Key].Applies -eq $True -and $Config["PolicyStates"][$Key].Preset -eq $True)
            {

                # Determine type of the policy and mark the preset appropriately

                if($Config["PolicyStates"][$Key].Type -eq [PolicyType]::SafeAttachments)
                {
                    $SAPreset = $Config["PolicyStates"][$Key].PresetLevel
                }

                if($Config["PolicyStates"][$Key].Type -eq [PolicyType]::SafeLinks)
                {
                    $SLPreset = $Config["PolicyStates"][$Key].PresetLevel
                }

                if($Config["PolicyStates"][$Key].Type -eq [PolicyType]::Malware)
                {
                    $MalwarePreset = $Config["PolicyStates"][$Key].PresetLevel
                }

                if($Config["PolicyStates"][$Key].Type -eq [PolicyType]::Antiphish)
                {
                    $AntiphishPreset = $Config["PolicyStates"][$Key].PresetLevel
                }


                if($Config["PolicyStates"][$Key].Type -eq [PolicyType]::Spam)
                {
                    $SpamPreset = $Config["PolicyStates"][$Key].PresetLevel
                }
            }

        }

        $msgApplies = "preset applies without exceptions";
        $msgNotApplies = "No preset applies or exceptions exist"

        # Safe Attachments
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.ConfigItem="Safe Attachments"

        if($SAPreset -ne $null)
        {
            $ConfigObject.ConfigData="$($SAPreset) $($msgApplies)"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
        } else {
            $ConfigObject.ConfigData=$msgNotApplies
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }

        $this.AddConfig($ConfigObject)

        # Safe Links
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.ConfigItem="Safe Links"

        if($SLPreset -ne $null)
        {
            $ConfigObject.ConfigData="$($SLPreset) $($msgApplies)"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
        } else {
            $ConfigObject.ConfigData=$msgNotApplies
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }

        $this.AddConfig($ConfigObject)

        # Malware
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.ConfigItem="Malware"

        if($MalwarePreset -ne $null)
        {
            $ConfigObject.ConfigData="$($MalwarePreset) $($msgApplies)"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
        } else {
            $ConfigObject.ConfigData=$msgNotApplies
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }

        $this.AddConfig($ConfigObject)

        # Antiphish
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.ConfigItem="Anti-phish"

        if($AntiphishPreset -ne $null)
        {
            $ConfigObject.ConfigData="$($AntiphishPreset) $($msgApplies)"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
        } else {
            $ConfigObject.ConfigData=$msgNotApplies
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }

        $this.AddConfig($ConfigObject)

        # Spam
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.ConfigItem="Spam"

        if($SpamPreset -ne $null)
        {
            $ConfigObject.ConfigData="$($SpamPreset) $($msgApplies)"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
        } else {
            $ConfigObject.ConfigData=$msgNotApplies
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }

        $this.AddConfig($ConfigObject)            

    }

}