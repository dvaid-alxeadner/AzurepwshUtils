<#
.SYNOPSIS
This is a script for extracting Azure Policy Compliance

.DESCRIPTION
Generate compliance data from Azure Policy in some ways useful in a SOC (Security Operations Center)

.PARAMETER 1
Scope string (Resource Group name, Management Group name, null)

.PARAMETER 2
Tenant ID

.PARAMETER 3
Application ID

.PARAMETER 4
.Secret of the App Registration

.PARAMETER 5
Subscription ID (Optional)

.PARAMETER 6
Boolean for scope resource as a management group or not (True/false)

.EXAMPLE
PS> .\AZPolicyCompliance.ps1

.NOTES
@2024

.LINK
https://github.com/dvaid-alxeadner/AzurepwshUtils/tree/main/AzurePolicies

#>
param ($scope=$false,$tenantID, $appId=$null, $secret=$null, $SubscriptionId,$typeScope=$false)

try {

    if ($TenantId -and $appId -and $secret) 
    {
        $sp = Get-AzADServicePrincipal -ApplicationId $appId
        $secret = ConvertTo-SecureString $secret -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($sp.AppId, $secret)

        if ($typeScope)
        {
            # Connect To Azure (Interactive Login)
            $loginAZ=Connect-AzAccount -ServicePrincipal -Credential $psCred -Tenant $TenantId
            $mg = Get-AzManagementGroup -GroupName $scope -ErrorAction SilentlyContinue
            $SubscriptionId=$null

            if($loginAZ)
            {
                if($mg.Id)
                {
                    $pol=Get-AzPolicyState -ManagementGroupName $mg.Name -Filter "PolicyDefinitionName ne '0868462e-646c-4fe3-9ced-a733534b6a2c' 
		    	AND PolicyDefinitionName ne 'd6b2009e-9ca0-446a-acce-f34213f7b803' AND PolicyDefinitionName ne '1c210e94-a481-4beb-95fa-1571b434fb04' 
       			AND PolicyDefinitionName ne '053d3325-282c-4e5c-b944-24faffd30d77' AND PolicyDefinitionName ne 'a6cf7411-da9e-49e2-aec0-cba0250eaf8c'
	  		AND PolicyDefinitionName ne '11ac78e3-31bc-4f0c-8434-37ab963cea07' AND PolicyDefinitionName ne '32133ab0-ee4b-4b44-98d6-042180979d50' 
                        AND PolicyDefinitionName ne 'cccc23c7-8427-4f53-ad12-b6a63eb452b3' AND PolicyDefinitionName ne 'e765b5de-1225-4ba3-bd56-1ac6695af988' 
                        AND PolicyDefinitionName ne '96670d01-0a4d-4649-9c89-2d3abc0a5025' AND PolicyDefinitionName ne '5e0640c5-c4f2-4e14-9f61-5c80ba586b8d'
                        AND PolicyDefinitionName ne 'e56962a6-4747-49cd-b67b-bf8b01975c4c' AND PolicySetDefinitionName ne '96670d01-0a4d-4649-9c89-2d3abc0a5025'
                        AND PolicySetDefinitionName ne '1f3afdf9-d0c9-4c3d-847f-89da613e70a8' AND PolicySetDefinitionName ne '1a5bb27d-173f-493e-9568-eb56638dde4d'"

                    if ($pol) 
                    {
                        
                        $outData = [System.Collections.Generic.List[Object]]::new()
                        $contador=0
                    
                        ForEach ($rows in $pol)
                        {
                            $contador++
                                
                            $prop=$rows.AdditionalProperties
                            $time=$rows.Timestamp
                            $resource=$rows.ResourceId
                            $policyId=$rows.PolicyAssignmentId
                            $policyName=$rows.PolicyAssignmentName
                            $policyDefName=$rows.PolicyDefinitionName
                            $policyCompliant=$rows.IsCompliant
                            $policySubscriptionId=$rows.SubscriptionId
                            $policyResourceType=$rows.ResourceType
                            $policyResourceGroup=$rows.ResourceGroup
                            $policyScope=$rows.PolicyAssignmentScope
                            $policyAction=$rows.PolicyDefinitionAction
                            $policyStateCompliance=$rows.ComplianceState

                            $policyDefinitionGroupNames=$rows.PolicyDefinitionGroupNames

                            $detail=Get-AzPolicyDefinition -Name $policyDefName -ErrorAction SilentlyContinue
                            $policyProperties=$detail.Properties

                            $policyDescription=$detail.Description
                            $policyDisplayName=$detail.DisplayName

                            if ($policyResourceGroup) 
                            {
                                $context=Set-AzContext -Subscription $policySubscriptionId
                                $ResourceGroup=Get-AzResourceGroup -Name $policyResourceGroup #-ErrorAction SilentlyContinue                                                             
                            }
                            else
                            {
                                $ResourceGroup=$false
                            }
                            
                            if ($ResourceGroup) 
                            {
                                $tags=$ResourceGroup.Tags
                                
                                if ($tags)
                                {
                                    if ($tags['PROYECTO']) 
                                    {
                                        $resourceGroupProyecto=$tags['PROYECTO']
                                    }
                                    else 
                                    {
                                        $resourceGroupProyecto="VACIO"
                                    }

                                    if ($tags['AMBIENTE']) 
                                    {
                                        $resourceGroupEnvironment=$tags['AMBIENTE']
                                    }
                                    else 
                                    {
                                        $resourceGroupEnvironment="VACIO"
                                    }

                                    if ($tags['LT']) {
                                        $resourceGroupLT=$tags['LT']
                                    }
                                    else 
                                    {
                                        $resourceGroupLT="VACIO"
                                    }
                                    
                                    if ($tags['OI']) 
                                    {
                                        $ResourceGroupOI=$tags['OI']
                                    }
                                    else 
						{
                                        $ResourceGroupOI="VACIO"
                                    }
                                }
                                else {
                                    $resourceGroupProyecto="VACIO"
                                    $resourceGroupEnvironment="VACIO"
                                    $resourceGroupLT="VACIO"
                                    $ResourceGroupOI="VACIO"
                                }
                            }
                            else 
                            {
                                $policyResourceGroup="NINGUNO"
                                $resourceGroupProyecto="VACIO"
                                $resourceGroupEnvironment="VACIO"
                                $resourceGroupLT="VACIO"
                                $ResourceGroupOI="VACIO"
                            }

                            $CustomData= [PSCustomObject][Ordered]@{
                                id=$policyDefName
                                datetime=$time
                                subscription=$policySubscriptionId
                                scope=$policyScope
                                resourceGroup=$policyResourceGroup
                                policyshortname=$policyName
                                policyfullname=$policyDisplayName
                                policyAction=$policyAction
                                resourcetype=$policyResourceType
                                resourcecompliance=$policyStateCompliance
                                resourcename=$resource
                                proyecto=$resourceGroupProyecto
                                ambiente=$resourceGroupEnvironment
                                lidertecnico=$resourceGroupLT
                                ordeinversion=$ResourceGroupOI
                                policyDescription=$policyDescription
                            }
                            $outData.Add($CustomData)
                            Write-Host ($CustomData | Format-Table | Out-String)
                        }
                    }    
                    else 
                    {
                        Write-Host "Failed to retrieve policy compliance under management group $scope"
                        exit 
                    }
                }
                else 
                {
                    Write-Host "Error: Management Group $scope Not Found"
                    exit 
                }
            }   
        }
        else 
        {
            if($SubscriptionId -imatch '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
            {
                if ($TenantId -imatch '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}') 
                {
                    # Connect To Azure (Interactive Login)
                    $loginAZ=Connect-AzAccount -ServicePrincipal -Credential $psCred -Tenant $TenantId -SubscriptionId $SubscriptionId

                    if ($loginAZ) 
                    { 
                        if ($scope)
                        {
                            $ResourceGroup = Get-AzResourceGroup -Name $scope -ErrorAction SilentlyContinue
                            if ($ResourceGroup) 
                            {
                                $pol=Get-AzPolicyState -ResourceGroupName $scope -Filter "PolicyDefinitionName ne '0868462e-646c-4fe3-9ced-a733534b6a2c' 
				AND PolicyDefinitionName ne 'd6b2009e-9ca0-446a-acce-f34213f7b803' AND PolicyDefinitionName ne '1c210e94-a481-4beb-95fa-1571b434fb04' 
				AND PolicyDefinitionName ne '053d3325-282c-4e5c-b944-24faffd30d77' AND PolicyDefinitionName ne 'a6cf7411-da9e-49e2-aec0-cba0250eaf8c'
                                AND PolicyDefinitionName ne '11ac78e3-31bc-4f0c-8434-37ab963cea07' AND PolicyDefinitionName ne '32133ab0-ee4b-4b44-98d6-042180979d50' 
                                AND PolicyDefinitionName ne 'cccc23c7-8427-4f53-ad12-b6a63eb452b3' AND PolicyDefinitionName ne 'e765b5de-1225-4ba3-bd56-1ac6695af988' 
                                AND PolicyDefinitionName ne '96670d01-0a4d-4649-9c89-2d3abc0a5025' AND PolicyDefinitionName ne '5e0640c5-c4f2-4e14-9f61-5c80ba586b8d'
                                AND PolicyDefinitionName ne 'e56962a6-4747-49cd-b67b-bf8b01975c4c' AND PolicySetDefinitionName ne '96670d01-0a4d-4649-9c89-2d3abc0a5025'
                                AND PolicySetDefinitionName ne '1f3afdf9-d0c9-4c3d-847f-89da613e70a8' AND PolicySetDefinitionName ne '1a5bb27d-173f-493e-9568-eb56638dde4d'"
                            }
                            else 
                            {
                                Write-Host "Invalid scope $scope"
                                exit 
                            }

                            $outData = [System.Collections.Generic.List[Object]]::new()
                            $contador=0
                        
                            ForEach ($rows in $pol)
                            {
                                $contador++
                                    
                                $prop=$rows.AdditionalProperties
                                $time=$rows.Timestamp
                                $resource=$rows.ResourceId
                                $policyId=$rows.PolicyAssignmentId
                                $policyName=$rows.PolicyAssignmentName
                                $policyDefName=$rows.PolicyDefinitionName
                                $policyCompliant=$rows.IsCompliant
                                $policySubscriptionId=$rows.SubscriptionId
                                $policyResourceType=$rows.ResourceType
                                $policyResourceGroup=$rows.ResourceGroup
                                $policyScope=$rows.PolicyAssignmentScope
                                $policyAction=$rows.PolicyDefinitionAction
                                $policyStateCompliance=$rows.ComplianceState

                                $policyDefinitionGroupNames=$rows.PolicyDefinitionGroupNames

                                $detail=Get-AzPolicyDefinition -Name $policyDefName
                                $policyProperties=$detail.Properties

                                $policyDescription=$detail.Description
                                $policyDisplayName=$detail.DisplayName
                                $tags=$ResourceGroup.Tags

                                if ($tags['PROYECTO']) 
                                {
                                    $resourceGroupProyecto=$tags['PROYECTO']
                                }
                                else 
                                {
                                    $resourceGroupProyecto="VACIO"
                                }

                                if ($tags['AMBIENTE']) 
                                {
                                    $resourceGroupEnvironment=$tags['AMBIENTE']
                                }
                                else 
                                {
                                    $resourceGroupEnvironment="VACIO"
                                }

                                if ($tags['LT']) {
                                    $resourceGroupLT=$tags['LT']
                                }
                                else 
                                {
                                    $resourceGroupLT="VACIO"
                                }
                                
                                if ($tags['OI']) 
                                {
                                    $ResourceGroupOI=$tags['OI']
                                }
                                else {
                                    $ResourceGroupOI="VACIO"
                                }
                            
                                $CustomData= [PSCustomObject][Ordered]@{
                                    id=$policyDefName
                                    datetime=$time
                                    subscription=$policySubscriptionId
                                    scope=$policyScope
                                    resourceGroup=$policyResourceGroup
                                    policyshortname=$policyName
                                    policyfullname=$policyDisplayName
                                    policyAction=$policyAction
                                    resourcetype=$policyResourceType
                                    resourcecompliance=$policyStateCompliance
                                    resourcename=$resource
                                    proyecto=$resourceGroupProyecto
                                    ambiente=$resourceGroupEnvironment
                                    lidertecnico=$resourceGroupLT
                                    ordeinversion=$ResourceGroupOI
                                    policyDescription=$policyDescription
                                }
                                
                                $outData.Add($CustomData)
                            }

                        }
                        else 
                        {
                            $pol=Get-AzPolicyState -SubscriptionId $SubscriptionId -Filter "PolicyDefinitionName ne '0868462e-646c-4fe3-9ced-a733534b6a2c' 
			    	AND PolicyDefinitionName ne '1c210e94-a481-4beb-95fa-1571b434fb04' AND PolicyDefinitionName ne 'd6b2009e-9ca0-446a-acce-f34213f7b803'			   
				AND PolicyDefinitionName ne '053d3325-282c-4e5c-b944-24faffd30d77' AND PolicyDefinitionName ne 'a6cf7411-da9e-49e2-aec0-cba0250eaf8c'
                            	AND PolicyDefinitionName ne '11ac78e3-31bc-4f0c-8434-37ab963cea07' AND PolicyDefinitionName ne '32133ab0-ee4b-4b44-98d6-042180979d50' 
                            	AND PolicyDefinitionName ne 'cccc23c7-8427-4f53-ad12-b6a63eb452b3' AND PolicyDefinitionName ne 'e765b5de-1225-4ba3-bd56-1ac6695af988' 
                            	AND PolicyDefinitionName ne '96670d01-0a4d-4649-9c89-2d3abc0a5025' AND PolicyDefinitionName ne '5e0640c5-c4f2-4e14-9f61-5c80ba586b8d'
                            	AND PolicyDefinitionName ne 'e56962a6-4747-49cd-b67b-bf8b01975c4c' AND PolicySetDefinitionName ne '96670d01-0a4d-4649-9c89-2d3abc0a5025'
                            	AND PolicySetDefinitionName ne '1f3afdf9-d0c9-4c3d-847f-89da613e70a8' AND PolicySetDefinitionName ne '1a5bb27d-173f-493e-9568-eb56638dde4d'"

                            if ($pol) 
                            {
                                
                                $outData = [System.Collections.Generic.List[Object]]::new()
                                $contador=0
                            
                                ForEach ($rows in $pol)
                                {
                                    $contador++
                                        
                                    $prop=$rows.AdditionalProperties
                                    $time=$rows.Timestamp
                                    $resource=$rows.ResourceId
                                    $policyId=$rows.PolicyAssignmentId
                                    $policyName=$rows.PolicyAssignmentName
                                    $policyDefName=$rows.PolicyDefinitionName
                                    $policyCompliant=$rows.IsCompliant
                                    $policySubscriptionId=$rows.SubscriptionId
                                    $policyResourceType=$rows.ResourceType
                                    $policyResourceGroup=$rows.ResourceGroup
                                    $policyScope=$rows.PolicyAssignmentScope
                                    $policyAction=$rows.PolicyDefinitionAction
                                    $policyStateCompliance=$rows.ComplianceState

                                    $policyDefinitionGroupNames=$rows.PolicyDefinitionGroupNames

                                    $detail=Get-AzPolicyDefinition -Name $policyDefName -ErrorAction SilentlyContinue
                                    $policyProperties=$detail.Properties

                                    $policyDescription=$details.Description
                                    $policyDisplayName=$details.DisplayName

                                    if ($policyResourceGroup) 
                                    {
                                        $ResourceGroup = Get-AzResourceGroup -Name $policyResourceGroup -ErrorAction SilentlyContinue                                    
                                    }
                                    else 
						{
                                        $ResourceGroup=$false
                                    }
                                    
                                    if ($ResourceGroup) 
                                    {
                                        $tags=$ResourceGroup.Tags
                                        
                                        if ($tags)
                                        {
                                            if ($tags['PROYECTO']) 
                                            {
                                                $resourceGroupProyecto=$tags['PROYECTO']
                                            }
                                            else 
                                            {
                                                $resourceGroupProyecto="VACIO"
                                            }

                                            if ($tags['AMBIENTE']) 
                                            {
                                                $resourceGroupEnvironment=$tags['AMBIENTE']
                                            }
                                            else 
                                            {
                                                $resourceGroupEnvironment="VACIO"
                                            }

                                            if ($tags['LT']) {
                                                $resourceGroupLT=$tags['LT']
                                            }
                                            else 
                                            {
                                                $resourceGroupLT="VACIO"
                                            }
                                            
                                            if ($tags['OI']) 
                                            {
                                                $ResourceGroupOI=$tags['OI']
                                            }
                                            else {
                                                $ResourceGroupOI="VACIO"
                                            }
                                        }
                                        else {
                                            $resourceGroupProyecto="VACIO"
                                            $resourceGroupEnvironment="VACIO"
                                            $resourceGroupLT="VACIO"
                                            $ResourceGroupOI="VACIO"
                                        }
                                    }
                                    else 
                                    {
                                        $policyResourceGroup="NINGUNO"
                                        $resourceGroupProyecto="VACIO"
                                        $resourceGroupEnvironment="VACIO"
                                        $resourceGroupLT="VACIO"
                                        $ResourceGroupOI="VACIO"
                                    }

                                    $CustomData= [PSCustomObject][Ordered]@{
                                        id=$policyDefName
                                        datetime=$time
                                        subscription=$policySubscriptionId
                                        scope=$policyScope
                                        resourceGroup=$policyResourceGroup
                                        policyshortname=$policyName
                                        policyfullname=$policyDisplayName
                                        policyAction=$policyAction
                                        resourcetype=$policyResourceType
                                        resourcecompliance=$policyStateCompliance
                                        resourcename=$resource
                                        proyecto=$resourceGroupProyecto
                                        ambiente=$resourceGroupEnvironment
                                        lidertecnico=$resourceGroupLT
                                        ordeinversion=$ResourceGroupOI
                                        policyDescription=$policyDescription
                                    }
                                    $outData.Add($CustomData)
                                    Write-Host ($CustomData | Format-Table | Out-String)
                                }
                            }    
                            else 
                            {
                                Write-Host "Invalid subscription $SubscriptionId"
                                exit 
                            }
                        }
                    }
                }
                else 
                {
                    Write-Host "Error:Tenant ID provided fails to comply the defined regular expression"
                    exit 
                }
            }
            else 
            {
                Write-Host "Error:Subscription ID provided fails to comply the defined regular expression"
                exit 
            }
        }
    }

    $outData | Sort {$_.Timestamp -as [datetime]} | Select id,datetime,subscription,scope,resourcegroup,policyshortname,policyfullname,policyaction,resourcetype,resourcecompliance,resourcename,proyecto,ambiente,lidertecnico,ordeinversion,policydescription  | Out-GridView

    Write-Host $contador
}
catch {
    Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils"
    exit 
}
