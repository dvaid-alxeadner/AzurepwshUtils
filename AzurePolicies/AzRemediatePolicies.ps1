param ($scope='aabbccdd-aabb-ccdd-eeff-aabbccddeeff',$sID='aabbccdd-aabb-ccdd-eeff-aabbccddeeff', $TenantP='aabbccdd-aabb-ccdd-eeff-aabbccddeeff', $location='East Us 2', $ObjID='aabbccdd-aabb-ccdd-eeff-aabbccddeeff', $excludedRG="RESOURCE_GROUP", $excludedTypes=("Microsoft.ContainerRegistry/registries","Microsoft.KeyVault/vaults","Microsoft.Compute/virtualMachines"), $excludedPolicies=("2b9ad585-36bc-4615-b300-fd4435808332","c75248c1-ea1d-4a9c-8fc9-29a6aabd5da8"))

try {

    if ($scope -imatch '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}') 
    {
        $SubscriptionId=$scope
        # Connect To Azure Subscription (Interactive Login)
        Connect-AzAccount -Tenant $TenantP -SubscriptionId $SubscriptionId
        # Get all the noncompliant policies
        $nonCompliantPolicies = Get-AzPolicyState -SubscriptionId $SubscriptionId -Filter "ComplianceState eq 'NonCompliant' and PolicySetDefinitionName ne '1f3afdf9-d0c9-4c3d-847f-89da613e70a8' and PolicySetDefinitionName ne '1a5bb27d-173f-493e-9568-eb56638dde4d'"
    }
    else 
    {
        $RG=$scope
        $SubscriptionId=$sID    
        # Connect To Azure Subscription (Interactive Login)
        Connect-AzAccount -Tenant $TenantP -SubscriptionId $SubscriptionId
        # Get the noncompliant policies on Resource Group
        $nonCompliantPolicies = Get-AzPolicyState -SubscriptionId $SubscriptionId -ResourceGroupName $RG -Filter "ComplianceState eq 'NonCompliant' and PolicySetDefinitionName ne '1f3afdf9-d0c9-4c3d-847f-89da613e70a8' and PolicySetDefinitionName ne '1a5bb27d-173f-493e-9568-eb56638dde4d'"
    }

    if ($nonCompliantPolicies) 
    {
        foreach ($policy in $nonCompliantPolicies) 
        {
            
            $output=$null
            $RG=$null

            if ($policy.PolicyDefinitionName -notin $excludedPolicies)
            {
                $RG=$policy.ResourceGroup
                
                if ($policy.ResourceType -notin $excludedTypes)
                {
                    # 1) FTPS should be required in your Web App
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/4d24b6d4-5e53-4a4f-a7f4-618fa573ee4b")
                    {
                        $App=Get-AzResource -ResourceId $policy.ResourceId
                        $Wname=$App.ResourceName.Trim()
                        
                        if ($RG -notin $excludedRG)
                        {
                            $output=Set-AzWebApp -ResourceGroupName $policy.ResourceGroup -Name $Wname -FtpsState "FtpsOnly"
                            
                            if ($output) 
                            {
                                Write-Host "Succesfully remediated FTPS Only Policy in "$Wname" under resource group "$RG
                            }
                            else
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for FTPS Only Policy in "$Wname" under resource group "$RG
                            }
                        }
                        else
                        {
                            Write-Host $Wname" is in excluded Resource Group "$RG
                        }
                    }

                    # 2) FTPS should be required in your Function App
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/399b2637-a50f-4f95-96f8-3a145476eb15")
                    {
                        $App=Get-AzResource -ResourceId $policy.ResourceId
                        $Fname=$App.ResourceName
                
                        if ($RG -notin $excludedRG)
                        {
                            $output=Set-AzWebApp -ResourceGroupName $RG -Name $Fname -FtpsState "FtpsOnly"

                            if ($output) 
                            {
                                Write-Host "Succesfully remediated FTPS Only Policy in "$Fname" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for FTPS Only Policy in "$Fname" under resource group "$RG
                            }
                        }
                        else 
                        {
                            Write-Host $Wnam" is in excluded Resource Group"$RG
                        }
                    }

                    # 3) HTTPS should be required in your Function App
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/6d555dd1-86f2-4f1c-8ed7-5abae7c6cbab")
                    {
                        $App=Get-AzResource -ResourceId $policy.ResourceId
                        $Fname=$App.ResourceName
                        
                        if ($RG -notin $excludedRG)
                        {
                            $output=Set-AzWebApp -ResourceGroupName $RG -Name $Fname -HttpsOnly $true

                            if ($output) 
                            {
                                Write-Host "Succesfully remediated HTTPS Only Policy in "$Fname" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for HTTPS Only Policy in "$Fname" under resource group "$RG
                            }    
                        }
                        else
                        {
                            Write-Host $Fname" is in excluded Resource Group"$RG
                        }           
                    }

                    # 4) HTTPS should be required in your Web App
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/a4af4a39-4135-47fb-b175-47fbdf85311d")
                    {
                        $App=Get-AzResource -ResourceId $policy.ResourceId
                        $Wname=$App.ResourceName.Trim()

                        if ($RG -notin $excludedRG)
                        {
                            $output=Set-AzWebApp -ResourceGroupName $RG -Name $Wname -HttpsOnly $true

                            if ($output) 
                            {
                                Write-Host "Succesfully remediated HTTPS Only Policy in "$Wname" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for HTTPS Only Policy in "$Wname" under resource group "$RG
                            }
                        }
                        else
                        {
                            Write-Host $Wname" is in excluded Resource Group"$RG
                        }                
                    }

                    # 5) CORS should not allow every resource to access your Web Applications
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/5744710e-cc2f-4ee8-8809-3b11e89f4bc9")
                    {
                        $App=Get-AzResource -ResourceId $policy.ResourceId
                        $Wname=$App.ResourceName
                        $output=Get-AzWebApp -ResourceGroupName $RG -Name $Wname
                        $hostN=$output.DefaultHostName

                        if ($RG -notin $excludedRG) 
                        {
                            $allowedOrigins = @()
                            $allowedOrigins += "https://"+$hostN
                            $App.Properties.siteConfig.cors =  @{allowedOrigins =  @($allowedOrigins)
                                                            supportCredentials = $true}
                            $App | Set-AzResource -Force

                            Write-Host $App.Properties.siteConfig.cors.Values
                        }
                        else
                        {
                            Write-Host $Wname" is in excluded Resource Group"$RG
                        }       
                    }

                    # 6) Storage accounts should prevent shared key access
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/8c6a50c6-9ffd-4ae7-986f-5fa6111f9a54")
                    {
                        $StgAcc=Get-AzResource -ResourceId $policy.ResourceId

                        $StgName=$StgAcc.Name

                        if ($RG -notin $excludedRG) 
                        {
                            $output=Set-AzStorageAccount -ResourceGroupName $RG -AccountName $StgName -AllowSharedKeyAccess $false
                            
                            if ($output) 
                            {
                                Write-Host "Succesfully remediated Shared Key Access Policy in "$StgName" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for Shared Key Access Policy in "$StgName" under resource group "$RG
                            }
                        }
                        else
                        {
                            Write-Host $StgName" is in excluded Resource Group"$RG
                        }  
                    }

                    # 7) An Azure Active Directory Administrator
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/1f314764-cb73-4fc9-b863-8eca98ac36e9")
                    {
                        $sqlDB=Get-AzResource -ResourceId $policy.ResourceId

                        $sqlName=$sqlDB.Name

                        if ($RG -notin $excludedRG) 
                        {
                            $output=Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $RG -ServerName $sqlName -DisplayName "yvergara@postobon.com.co" -ObjectId $DBAObjID    
                            
                            if ($output) 
                            {
                                Write-Host "Succesfully remediated Azure SQL Admin Policy in "$sqlName" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for Azure SQL Admin Policy in "$sqlName" under resource group "$RG
                            }
                        }
                        else 
                        {
                            Write-Host $sqlName" is in excluded Resource Group"$RG
                        }
                    }

                    # 8) All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/a1817ec0-a368-432a-8057-8371e17ac6ee")
                    {
                        $AuthRuleSBus=Get-AzResource -ResourceId $policy.ResourceId
                        $nameSpaceParent=$AuthRuleSBus.ParentResource
                        $index=$nameSpaceParent.IndexOf("/")
                        $len=$nameSpaceParent.ToString().Length
                        $nameSpace=$nameSpaceParent.ToString().SubString($index+1,$len-$index-1)  
                        $AuthRuleSBusName=$AuthRuleSBus.Name
                    
                        if ($RG -notin $excludedTypes) 
                        {
                            Remove-AzServiceBusAuthorizationRule -ResourceGroupName $RG -Namespace $nameSpace -Name $AuthRuleSBusName -Force
                            
                             Write-Host $rule" Removed From Authorization rules in "$AuthRuleSBusName" under resource group "$RG
                        }
                        else 
                        {
                            Write-Host $nameSpace" is in excluded Resource Group"$RG
                        }
                    }

                    # 9) Azure SQL Database should have the minimal TLS version of 1.2
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/32e6bbec-16b6-44c2-be37-c5b672d103cf")
                    {
                        $sqlDB=Get-AzResource -ResourceId $policy.ResourceId

                        $sqlName=$sqlDB.Name

                        if ($RG -notin $excludedTypes) 
                        {
                            $output=Set-AzSqlServer -ServerName $sqlName -ResourceGroupName $RG -MinimalTlsVersion "1.2"

                            if ($output) 
                            {
                                Write-Host "Succesfully remediated Azure SQL TLS 1.2 Policy in "$sqlName" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for Azure SQL TLS 1.2 Policy in "$sqlName" under resource group "$RG
                            }
                        }
                        else 
                        {
                            Write-Host $sqlName" is in excluded Resource Group"$RG
                        }
                    }

                    # 10) Azure Service Bus namespaces should have local authentication methods disabled
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/cfb11c26-f069-4c14-8e36-56c394dae5af")
                    {
                        $SB=Get-AzResource -ResourceId $policy.ResourceId

                        $SBName=$SB.Name

                        if ($RG -notin $excludedTypes) 
                        {
                            $output=Set-AzServiceBusNamespace -ResourceGroup $SG -NamespaceName $SBName -DisableLocalAuth   
                            
                            if ($output) 
                            {
                                Write-Host "Succesfully remediated Service Bus Local Auth Policy in "$SBName" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for Service Bus Local Auth Policy in "$SBName" under resource group "$RG
                            } 
                        }
                        else 
                        {
                            Write-Host $SBName" is in excluded Resource Group"$RG
                        }
                    }

                    # 11) Transparent Data Encryption on SQL databases should be enabled
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/17k78e20-9358-41c9-923c-fb736d382a12")
                    {
                        $sqlDB=Get-AzResource -ResourceId $policy.ResourceId

                        $sqlName=$sqlDB.Name
                        
                        $Server=$sqlDB.ParentResource
                        
                        $index=$Server.IndexOf("/")
                        $len=$Server.ToString().Length
                        $SQLServer=$Server.ToString().SubString($index+1,$len-$index-1)  

                        if ($RG -notin $excludedTypes) 
                        {
                            $output=Set-AzSqlDatabaseTransparentDataEncryption -ServerName $SQLServer -DatabaseName $sqlName -ResourceGroup $RG -State Enabled

                            if ($output) 
                            {
                                Write-Host "Succesfully remediated Azure SQL TDE Policy in "$sqlName" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for Azure SQL TDE Policy in "$sqlName" under resource group "$RG
                            }
                        }
                        else
                        {
                            Write-Host $sqlName" is in excluded Resource Group"$RG
                        }
                    }

                    # 12) Subnets should be associated with a Network Security Group
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/e71308d3-144b-4262-b144-efdc3cc90517")
                    {
                        Write-Output $policy.ResourceGroup
                        Write-Output $policy.ResourceId

                        $SBnet=Get-AzResource -ResourceId $policy.ResourceId
                        $SBnetName=$SBnet.Name
                        $AddressPre=$SBnet.Properties.addressPrefix

                        $VnetSBNet=$SBnet.ParentResource
                        
                        $index=$VnetSBNet.IndexOf("/")
                        $len=$VnetSBNet.ToString().Length
                        $Vnet=$VnetSBNet.ToString().SubString($index+1,$len-$index-1)  
                        
                        $VnetPSObject=Get-AzVirtualNetwork -Name $Vnet -ResourceGroupName $RG
                        $location=$VnetPSObject.Location

                        $ruleInbound=New-AzNetworkSecurityRuleConfig -Name "DENYINBOUNDNSG" -Description "Automatically Generated" -Access Deny -Protocol * -Direction Inbound -Priority 100 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange *
                        $ruleOutbound=New-AzNetworkSecurityRuleConfig -Name "DENYOUTBOUNDNSG" -Description "Automatically Generated" -Access Deny -Protocol * -Direction Outbound -Priority 100 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange *

                        $nsg=New-AzNetworkSecurityGroup -ResourceGroupName $RG -Location $location -Name "DENYAUTONSG" -SecurityRules $ruleInbound,$ruleOutbound

                        $output=Set-AzVirtualNetworkSubnetConfig -VirtualNetwork $VnetPSObject -AddressPrefix $AddressPre -Name $SBnetName -NetworkSecurityGroup $nsg

                        if ($output) 
                        {
                            Write-Host "Succesfully remediated NSG Policy in "$SBnetName" under resource group "$RG
                        }
                        else 
                        {
                            Write-Output "`a"
                            Write-Host "Remediation failed for NSG Policy in "$SBnetName" under resource group "$RG
                        }
                    }

                    # 13) Secure transfer to storage accounts should be enabled
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/404c3081-a854-4457-ae30-26a93ef643f9")
                    {
                        $StgAcc=Get-AzResource -ResourceId $policy.ResourceId
                        $StgName=$StgAcc.Name

                        if ($RG -notin $excludedRG) 
                        {
                            $output=Set-AzStorageAccount -ResourceGroupName $RG -AccountName $StgName -EnableHttpsTrafficOnly $true  
                            
                            if ($output) 
                            {
                                Write-Host "Succesfully remediated Secure Transfer Policy in "$StgName" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for Secure Transfer Policy in "$StgName" under resource group "$RG
                            }
                        }
                        else 
                        {
                            Write-Host $StgName" is in excluded Resource Group"$RG
                        }
                    }

                    # 14) Storage account public access should be disallowed
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/4fa4b6c0-31ca-4c0d-b10d-24b96f62a751")
                    {
                        $StgAcc=Get-AzResource -ResourceId $policy.ResourceId
                        $StgName=$StgAcc.Name

                        if ($RG -notin $excludedRG)
                        {
                            Set-AzStorageAccount -ResourceGroupName $RG -AccountName $StgName -AllowBlobPublicAccess $false -AllowCrossTenantReplication $false -AllowSharedKeyAccess $false
                            $output=Set-AzStorageAccount -ResourceGroupName $RG -AccountName $StgName -PublicNetworkAccess Disabled

                            if ($output) 
                            {
                                Write-Host "Succesfully remediated Public Storage Account Policy in "$StgName" under resource group "$RG
                            }
                            else 
                            {
                                Write-Output "`a"
                                Write-Host "Remediation failed for Public Storage Account Policy in "$StgName" under resource group "$RG
                            }
                        }
                        else 
                        {
                            Write-Host $StgName" is in excluded Resource Group"$RG
                        }
                    }

                    # 15) Cognitive Services accounts should use a managed identity
                    if($policy.PolicyDefinitionId -eq "/providers/microsoft.authorization/policydefinitions/fe3fd216-4f83-4fc1-8984-2bbec80a3418")
                    {
                        $cgService=Get-AzResource -ResourceId $policy.ResourceId 
                        $cgServiceName=$cgService.Name

                        if ($RG -notin $excludedRG)
                        {
                            $output=Set-AzCognitiveServicesAccount -ResourceGroupName $RG -Name $cgServiceName -AssignIdentity -IdentityType SystemAssigned

                            if ($output) 
                            {
                                Write-Host "Succesfully remediated Managed Identity Policy for "$cgServiceName" under resource group "$RG
                            }
                            else 
                            {   
                                Write-Output "`a"
                                Write-Host "Remediation failed Managed Identity Policy for in "$cgServiceName" under resource group "$RG
                            }
                        }
                        else 
                        {
                            Write-Host $cgServiceName" is in excluded Resource Group"$RG
                        }
                    }
                }
            }
        }
    }
    else 
    {
        Write-Host "No policies found in scope "$scope
    }
}
Catch
{
    Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils" 
    exit 
}