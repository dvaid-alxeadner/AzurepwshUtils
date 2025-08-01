<#
.SYNOPSIS
This is a script for creating Azure Policies.

.DESCRIPTION
Deploy Azure Policies in a subscription for a given tenant_id and subscription_id or management group
Only 200 policies can be created in a defined scope (Management Group or Subscription). The 201 policy will trigger the PolicyAssignmentQuotaExceeded error.

.PARAMETER 1
Tenant ID

.PARAMETER 2
Boolen for scope resource as a management group or not (True/false)

.PARAMETER 3
Scope string (Resource Group name, Management Group name, null)

.PARAMETER 4
Subscription ID (Optional)

.EXAMPLES:
To deploy policies in a resource Group:

PS> .\CreatePolicies.ps1 aaaaaaaa-bbbb-cccc-eeee-fffffffffff $false "Resource Group (Optional)" aaaaaaaa-bbbb-cccc-eeee-fffffffffff (Optional)

To deploy policies in a Management Group:

PS> .\AzCreatePolicies.ps1 -TenantId aaaaaaaa-bbbb-cccc-eeee-fffffffffff -flagMG $false -scope "Management Group Name" -SubscriptionId $null


.NOTES
@2021

.LINK
github.com/dvaid-alxeadner/AzurepwshUtils/tree/main/AzurePolicies

#>
param ($TenantId=$n,$flagMG=$false,$scope=$null,$SubscriptionId=$null)

function ManageAzPolicy{ 
 
    Param ([string]$policyDefId,[string]$Description,[string]$policyName,[string]$scope,[string]$displayName,[string]$policySupportMessage=$null,[string]$effect=$null,$arrayParams=$null,[string]$nameParam)
    
    try
    {
        $definition = Get-AzPolicyDefinition | Where-Object { $_.Id -eq $policyDefId }    

        if ($definition) 
        {
            $NonComplianceMessages = @{Message=$Description}

            $val = Get-AzPolicyAssignment -Name $policyName -Scope $scope -ErrorAction SilentlyContinue

            if (-not $val) 
            {
                if ($effect) 
                {
                    if ($policySupportMessage) 
                    {
                        if ($arrayParams -and $nameParam)  
                        {
                            $pol = New-AzPolicyAssignment -Name $policyName -DisplayName $displayName -Description $Description -PolicyDefinition $definition -Scope $scope -EnforcementMode Default -NonComplianceMessage $NonComplianceMessages -PolicyParameterObject @{"effect" = $effect; $nameParam=$arrayParams}
                        }
                        else 
                        {
                            $pol = New-AzPolicyAssignment -Name $policyName -DisplayName $displayName -Description $Description -PolicyDefinition $definition -Scope $scope -EnforcementMode Default -NonComplianceMessage $NonComplianceMessages -PolicyParameterObject @{"effect"="$effect"}
                        }
                    }
                    else 
                    {
                        if ($arrayParams -and $nameParam) 
                        {
                            $pol = New-AzPolicyAssignment -Name $policyName -DisplayName $displayName -Description $Description -PolicyDefinition $definition -Scope $scope -EnforcementMode Default -PolicyParameterObject @{"effect" = $effect; $nameParam=$arrayParams}
                        }
                        else
                        {
                            $pol = New-AzPolicyAssignment -Name $policyName -DisplayName $displayName -Description $Description -PolicyDefinition $definition -Scope $scope -EnforcementMode Default -PolicyParameterObject @{"effect"="$effect"}
                        }
                    }
                }
                else 
                {
                    if ($policySupportMessage) 
                    {
                        if ($arrayParams -and $nameParam) 
                        {
                            $pol = New-AzPolicyAssignment -Name $policyName -DisplayName $displayName -Description $Description -PolicyDefinition $definition -Scope $scope -EnforcementMode Default -NonComplianceMessage $NonComplianceMessages -PolicyParameterObject @{$nameParam=$arrayParams}
                        }
                        else 
                        {
                            $pol = New-AzPolicyAssignment -Name $policyName -DisplayName $displayName -Description $Description -PolicyDefinition $definition -Scope $scope -EnforcementMode Default -NonComplianceMessage $NonComplianceMessages
                        }    
                    }
                    else 
                    {
                        if ($arrayParams -and $nameParam) 
                        {
                            $pol = New-AzPolicyAssignment -Name $policyName -DisplayName $displayName -Description $Description -PolicyDefinition $definition -Scope $scope -EnforcementMode Default -PolicyParameterObject @{$nameParam=$arrayParams}
                        }
                        else 
                        {
                            $pol = New-AzPolicyAssignment -Name $policyName -DisplayName $displayName -Description $Description -PolicyDefinition $definition -Scope $scope -EnforcementMode Default
                        }
                    }
                }
                $policyName=$pol.Name
                $policyId=$definition.PolicyDefinitionId
                Write-Host "$policyName $policyId `n"
            }
            else 
            {
                Write-Host "Policy $policyName already exists in $scope" "`a"
            }
        }
        else 
        {
            Write-Host "Cannot create Policy, Microsoft removed policy definition under ID $policyDefId" "`n" 
        }
    }
    catch 
    {
        Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
        Write-Host "Function Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils"
        Write-Host "`n"
    }
}

try {

    if ($flagMG) 
    {
        # Connect To Azure (Interactive Login)
        $loginAZ=Connect-AzAccount -Tenant $TenantId

        $mg = Get-AzManagementGroup -GroupName $scope -ErrorAction SilentlyContinue
        $scope = $mg.Id
        $SubscriptionId=$null
    }
    else 
    {
        if($SubscriptionId -imatch '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
        {
            if ($TenantId -imatch '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}') 
            {
                # Connect To Azure (Interactive Login)
                $loginAZ=Connect-AzAccount -Tenant $TenantId -SubscriptionId $SubscriptionId

                if ($loginAZ) 
                { 
                    if ($scope)
                    {
                        $ResourceGroup = Get-AzResourceGroup -Name $scope -ErrorAction SilentlyContinue
                        
                        if ($ResourceGroup) 
                        {
                            $scope=$ResourceGroup.ResourceId
                        }
                        else 
                        {
                            Write-Host "Invalid scope.  Resource group $scope not found in subscription $SubscriptionId"
                            exit 
                        }
                    }
                    else 
                    {
                        $scope="/subscriptions/$($SubscriptionId)"
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
    
    if ($loginAZ)
    {
        
        # [Preview]: Storage account public access should be disallowed 
        # Effect DENY
        $policyName = "deny-publicaccess-strg"
        $displayName = "1) [Preview]: Storage account public access should be disallowed"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las cuentas de storage deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4fa4b6c0-31ca-4c0d-b10d-24b96f62a751" $Description $policyName $scope $displayName "Y" "Deny"

        # Microsoft Defender for Storage should be enabled
        # Effect AuditIfNotExists
        $policyName = "audit-mdfs-strg"
        $displayName = "2) Microsoft Defender for Storage should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage deben tener habilitado el Microsoft Defender."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/640d2586-54d2-465f-877f-9ffc1d2109f4" $Description $policyName $scope $displayName "Y" 
        
        # Secure transfer to storage accounts should be enabled 
        # Effect Audit
        $policyName = "deny-sectransf-strg"
        $displayName = "3) Secure transfer to storage accounts should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las cuentas de almacenamiento deben tener habilitado el Secure Transfer."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9" $Description $policyName $scope $displayName "Y" "Audit"

        # Storage accounts should allow access from trusted Microsoft services 
        # Effect DENY
        $policyName = "deny-mstrusted-strg"
        $displayName = "4) Storage accounts should allow access from trusted Microsoft services"
        $Description = "Para cumplir la linea base de seguridad de azure las cuentas de storage deben permitir el acceso desde los servicios de Microsoft confiables y que implementen autenticacion fuerte."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c9d007d0-c057-4772-b18c-01e546713bcd" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Storage accounts should prevent shared key access 
        # Effect DENY
        $policyName = "deny-SASdisable-strg"
        $displayName = "5) Storage accounts should prevent shared key access"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage deben tener deshabilitado el soporte de llaves de acceso, en su lugar se debe usar Azure AD."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8c6a50c6-9ffd-4ae7-986f-5fa6111f9a54" $Description $policyName $scope $displayName "Y" "Deny"

        # Storage accounts should prevent cross tenant object replication 
        # Effect DENY
        $policyName = "deny-repcten-strg"
        $displayName = "6) Storage accounts should prevent cross tenant object replication"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage deben evitar la replicacion de objetos cross tenant."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/92a89a79-6c52-4a7e-a03f-61306fc49312" $Description $policyName $scope $displayName "Y" "Deny"

        # Storage accounts should have infrastructure encryption 
        # Effect DENY
        $policyName = "deny-infraencrypt-strg"
        $displayName = "7) Storage accounts should have infrastructure encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage deben tener cifrado a nivel de infraestructura."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4733ea7b-a883-42fe-8cac-97454c2a9e4a" $Description $policyName $scope $displayName "Y" "Deny"

        # Require encryption on Data Lake Store accounts NO PARAMS
        $policyName = "deny-infraencrypt-dtlk"
        $displayName = "8) Require encryption on Data Lake Store accounts"
        $Description = "Para cumplir la linea base de seguridad de Azure los data lake deben tener cifrado a nivel de infraestructura."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a7ff3161-0087-490a-9ad9-ad6217f4f43a" $Description $policyName $scope $displayName "Y"

        # Storage accounts should have the specified minimum TLS version
        # Effect DENY
        $policyName = "deny-tls12-strg"
        $displayName = "9) Storage accounts should have the specified minimum TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage no deben soportar versiones obsoletas de TLS."
        $minTLS = "TLS1_2"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fe83a0eb-a853-422d-aac2-1bffd182c5d0" $Description $policyName $scope $displayName "Y" "Deny" $minTLS "minimumTlsVersion"

        # Function apps should require FTPS only 
        # Effect AuditIfNotExists
        $policyName = "audit-ftps-funcapp"
        $displayName = "10) FTPS only should be required in your Function App"
        $Description = "Para cumplir la linea base de seguridad de Azure ninguna Function App debe usar FTP en los despliegues."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/399b2637-a50f-4f95-96f8-3a145476eb15" $Description $policyName $scope $displayName "Y"

        # Function apps should only be accessible over HTTPS
        # Effect Deny
        $policyName = "deny-https-funcapp"
        $displayName = "11) Function apps should only be accessible over HTTPS"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las Function App deben tener habilitado el https only."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6d555dd1-86f2-4f1c-8ed7-5abae7c6cbab" $Description $policyName $scope $displayName "Y" "Deny"

        # Function apps should have remote debugging turned off
        # Effect AuditIfNotExists
        $policyName = "audit-debug-funcapp"
        $displayName = "12) Function apps should have remote debugging turned off"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las Function App deben tener deshabilitado el debugging remoto."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0e60b895-3786-45da-8377-9c6b4b6ac5f9" $Description $policyName $scope $displayName "Y"
        
        # Latest TLS version should be used in your Function App
        # Effect AuditIfNotExists
        $policyName = "audit-tls-funcapp"
        $displayName = "13) Function apps should use the latest TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure las function app no deben soportar versiones obsoletas de TLS"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f9d614c5-c173-4d56-95a7-b4437057d193" $Description $policyName $scope $displayName "Y"

        # Function apps should not have CORS configured to allow every resource to access your apps
        # Effect AuditIfNotExists
        $policyName = "audit-cors-funcapp"
        $displayName = "14) CORS should not allow every resource to access your Function Apps"
        $Description = "Para cumplir la linea base de seguridad de Azure las function app no deben permitir el acceso desde todos los dominios CORS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0820b7b9-23aa-4725-a1ce-ae4558f718e5" $Description $policyName $scope $displayName "Y"

        # Function apps should have authentication enabled
        # Effect AuditIfNotExists
        $policyName = "audit-auth-funcapp"
        $displayName = "15) Function apps should have authentication enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las function app deben requerir autenticacion."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c75248c1-ea1d-4a9c-8fc9-29a6aabd5da8" $Description $policyName $scope $displayName "Y"

        # Function apps should use latest HTTP Version
        # Effect AuditIfNotExists
        $policyName = "audit-httpv-funcapp"
        $displayName = "16) Function apps should use latest HTTP Version"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las function deben utilizar unicamente la ultima version de HTTP."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e2c1c086-2d84-4019-bff3-c44ccd95113c" $Description $policyName $scope $displayName "Y"

        # Function apps should disable public network access
        # Effect DENY
        $policyName = "deny-publicacces-funcapp"
        $displayName = "17) Function apps should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las function app deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/969ac98b-88a8-449f-883c-2e9adb123127" $Description $policyName $scope $displayName "Y" "Deny"

        # Function app slots should only be accessible over HTTPS
        # Effect DENY
        $policyName = "deny-https-funcappslt"
        $displayName = "18) Function app slots should only be accessible over HTTPS"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slots deben tener ser accedidas solo por HTTPS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5e5dbe3f-2702-4ffc-8b1e-0cae008a5c71" $Description $policyName $scope $displayName "Y" "Deny"

        # Function app slots should disable public network access
        # Effect DENY
        $policyName = "deny-public-funcslt"
        $displayName = "19) Function app slots should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slot deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/11c82d0c-db9f-4d7b-97c5-f3f9aa957da2" $Description $policyName $scope $displayName "Y" "Deny"

        # Function app slots should have remote debugging turned off
        # Effect AuditIFNotExists
        $policyName = "audit-debug-funcappslt"
        $displayName = "20) Function app slots should have remote debugging turned off"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slot deben tener deshabilitado el debugging remoto."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/89691ef9-8c50-49a8-8950-9c7fba41699e" $Description $policyName $scope $displayName "Y"

        # Function app slots should not have CORS configured to allow every resource to access your apps
        # Effect AuditIfNotExists
        $policyName = "audit-cors-funcappslt"
        $displayName = "21) Function app slots should not have CORS configured to allow every resource to access your apps"
        $Description = "Para cumplir la linea base de seguridad de Azure los function app slot no deben permitir el acceso desde todos los dominios CORS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a1a22235-dd10-4062-bd55-7d62778f41b0" $Description $policyName $scope $displayName "Y"
  
        # Function app slots should use the latest TLS version
        # Effect AuditIFNotExists
        $policyName = "audit-tls12-funcappslt"
        $displayName = "22) Function app slots should use the latest TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure los function app slot no deben soportar versiones obsoletas de TLS"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/deb528de-8f89-4101-881c-595899253102" $Description $policyName $scope $displayName "Y"
        
        # Function app slots should require FTPS only
        # Effect AuditIFNotExists
        $policyName = "audit-ftps-funcappslt"
        $displayName = "23) Function app slots should require FTPS only"
        $Description = "Para cumplir la linea base de seguridad de Azure ningun function app slot debe usar FTP en los despliegues."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e1a09430-221d-4d4c-a337-1edb5a1fa9bb" $Description $policyName $scope $displayName "Y"

        # Function app slots should use latest HTTP Version
        # Effect AuditIFNotExists
        $policyName = "audit-httpv-funcappslt"
        $displayName = "24) Function app slots should use latest HTTP Version"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slots deben utilizar unicamente la ultima version de HTTP."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fa98f1b1-1f56-4179-9faf-93ad82f3458f" $Description $policyName $scope $displayName "Y"

        # Key vaults should have soft delete enabled
        # Effect DENY
        $policyName = "deny-softd-kv"
        $displayName = "25) Key vaults should have soft delete"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los key vault deben tener habilitado soft delete"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Resource logs in Key Vault should be enabled 
        # Effect AuditIfNotExists
        $policyName = "audit-reslogs-kv"
        $displayName = "26) Resource logs in Key Vault should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los key vault deben retener los logs del recurso por un periodo de tiempo superior a 90 dias."
        $requireRetentionDays = "90"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cf820ca0-f99e-4f3e-84fb-66e913812d21" $Description $policyName $scope $displayName "Y" "AuditIfNotExists" $requireRetentionDays "requiredRetentionDays"

        # Azure Defender for Key Vault should be enabled
        # Effect AuditIfNotExists
        $policyName = "audit-azdf-kv"
        $displayName = "27) Azure Defender for Key Vault should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los key vault deben tener habilitado Azure Defender"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0e6763cc-5078-4e64-889d-ff4d9a839047" $Description $policyName $scope $displayName "Y"
        
        # Key Vault secrets should have an expiration date
        # Effect DENY
        $policyName = "deny-expscr-kv"
        $displayName = "28) Key Vault secrets should have an expiration date"
        $Description = "Para cumplir la linea base de seguridad de Azure los secretos en los key vault deben tener configurada una fecha de expiracion."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/98728c90-32c7-4049-8429-847dc0f4fe37" $Description $policyName $scope $displayName $null "Deny"

        # Key Vault keys should have an expiration date
        # Effect DENY
        $policyName = "deny-expkey-kv"
        $displayName = "29) Key Vault keys should have an expiration date"
        $Description = "Para cumplir la linea base de seguridad de Azure las llaves en los Key Vault deben tener configurada una fecha de expiracion."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0" $Description $policyName $scope $displayName $null "Deny"

        # Azure Key Vault should disable public network access
        # Effect DENY
        $policyName = "deny-publicaccess-kv"
        $displayName = "30) Azure Key Vault should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de azure los key vault deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/405c5871-3e91-4644-8a63-58e19d68ff5b" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Key Vaults should use private link
        # Effect Audit
        $policyName = "audit-pendpoint-kv"
        $displayName = "31) Azure Key Vaults should use private link"
        $Description = "Para cumplir la linea base de seguridad de azure los key vault deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a6abeaec-4d90-4a02-805f-6b26c4d3fbe9" $Description $policyName $scope $displayName "Y"

        # Azure Data Factory linked services should use Key Vault for storing secrets
        # Effect Audit
        $policyName = "audit-kv-dtfy"
        $displayName = "32) Azure Data Factory linked services should use Key Vault for storing secrets"
        $Description = "Para cumplir la linea base de seguridad de Azure Data Factory debe utilizar Key Vault para almacenar secretos."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/127ef6d7-242f-43b3-9eef-947faf1725d0" $Description $policyName $scope $displayName "Y"

        # Azure Data Factory linked services should use system-assigned managed identity authentication when it is supported
        # Effect Audit
        $policyName = "audit-mngid-dtfy"
        $displayName = "33) Azure Data Factory linked services should use system-assigned managed identity authentication when it is supported"
        $Description = "Para cumplir la linea base de seguridad de Azure Data Factory debe utilizar system managed identity para conectarse a recursos."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f78ccdb4-7bf4-4106-8647-270491d2978a" $Description $policyName $scope $displayName "Y"

        # SQL Server Integration Services integration runtimes on Azure Data Factory should be joined to a virtual network
        # Effect Audit
        $policyName = "audit-ssisvnet-dtfy"
        $displayName = "34) SQL Server Integration Services integration runtimes on Azure Data Factory should be joined to a virtual network"
        $Description = "Para cumplir la linea base de seguridad de Azure los integration runtime SSIS en Data Factory deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0088bc63-6dee-4a9c-9d29-91cfdc848952" $Description $policyName $scope $displayName "Y" "Audit"

        # Public network access on Azure Data Factory should be disabled
        # Effect DENY
        $policyName = "deny-publicaccess-dtfy"
        $displayName = "35) Public network access on Azure Data Factory should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Factory deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1cf164be-6819-4a50-b8fa-4bcaa4f98fb6" $Description $policyName $scope $displayName "Y" "Deny"
    
        # Azure Data Factory linked service resource type should be in allow list
        # Effect DENY
        $policyName = "deny-lsallow-dtfy"
        $displayName = "36) Azure Data Factory linked service resource type should be in allow list"
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Factory solo deben utilizar conectores previamente aprobados."
        $allowedLinkedServicesArray =@("AzureBlobStorage","AzureDatabricks","AzureDataLakeStore","AzureKeyVault","AzureSqlDatabase","SqlServer")
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6809a3d0-d354-42fb-b955-783d207c62a8" $Description $policyName $scope $displayName "Y" "Deny" $allowedLinkedServicesArray "allowedLinkedServiceResourceTypes"

        # Azure Data Factory should use a Git repository for source control
        # Effect AuditIfNotExists
        $policyName = "audit-git-dtfy"
        $displayName = "37) Azure Data Factory should use a Git repository for source control"
        $Description = "Para cumplir la linea base de seguridad de Azure Data Factory debe utilizar un repositorio Git para control de versiones."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/77d40665-3120-4348-b539-3192ec808307" $Description $policyName $scope $displayName "Y"
     
        # Azure SQL Database should be running TLS version 1.2 or newer
        # Effect DENY
        $policyName = "deny-tls12-asql"
        $displayName = "38) Azure SQL Database should be running TLS version 1.2 or newer"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las bases de datos Azure SQL deben usar la ultima version disponible de TLS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/32e6bbec-16b6-44c2-be37-c5b672d103cf" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Defender for Azure SQL Database servers should be enabled
        # Effect AuditIfNotExists
        $policyName = "audit-azdf-asql"
        $displayName = "39) Azure Defender for Azure SQL Database servers should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener habilitado el Azure Defender."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/7fe3b40f-802b-4cdd-8bd4-fd799c948cc2" $Description $policyName $scope $displayName "Y"

        # An Azure Active Directory administrator should be provisioned for SQL servers
        # Effect AuditIfNotExists
        $policyName = "audit-aadadmin-asql"
        $displayName = "40) An Azure Active Directory administrator should be provisioned for SQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener configurado un administrador de Azure Active Directory"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1f314764-cb73-4fc9-b863-8eca98ac36e9" $Description $policyName $scope $displayName "Y"

        # SQL Managed Instance should have the minimal TLS version of 1.2
        # Effect Audit
        $policyName = "audit-tls-asqlmi"
        $displayName = "41) SQL Managed Instance should have the minimal TLS version of 1.2"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las bases de datos Azure SQL Managed deben usar la ultima version disponible de TLS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a8793640-60f7-487c-b5c3-1d37215905c4" $Description $policyName $scope $displayName "Y"

        # Transparent Data Encryption on SQL databases should be enabled
        # Effect AuditIfNotExists
        $policyName = "audit-tde-asql"
        $displayName = "42) Transparent Data Encryption on SQL databases should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las bases de datos Azure SQL deben tener habilitado TDE (Transparent Data Encryption)."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/17k78e20-9358-41c9-923c-fb736d382a12" $Description $policyName $scope $displayName "Y"
        
        # Azure SQL Database should have Microsoft Entra-only authentication enabled
        # Effect DENY
        $policyName = "deny-aadauth-asql"
        $displayName = "43) Azure SQL Database should have Microsoft Entra-only authentication enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben implementar Autenticacion de Microsoft Entra ID."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b3a22bc9-66de-45fb-98fa-00f5df42f41a" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure SQL Managed Instance should have Microsoft Entra-only authentication enabled
        # Effect DENY
        $policyName = "deny-aadauth-asqlmi"
        $displayName = "44) Azure SQL Managed Instance should have Microsoft Entra-only authentication enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL Managed deben implementar Autenticacion de Microsoft Entra ID"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0c28c3fb-c244-42d5-a9bf-f35f2999577b" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Public network access on Azure SQL Database should be disabled
        # Effect DENY
        $policyName = "deny-publicaccess-asql"
        $displayName = "45) Public network access on Azure SQL Database should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1b8ca024-1d5c-4dec-8995-b1a932b41780" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure SQL Managed Instances should disable public network access
        # Effect DENY
        $policyName = "deny-publicaccess-asqlmi"
        $displayName = "46) Azure SQL Managed Instances should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL Managed deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/9dfea752-dd46-4766-aed1-c355fa93fb91" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Defender for SQL servers on machines should be enabled
        # Effect AuditIFNotExists
        $policyName = "audit-azdfmach-asql"
        $displayName = "47) Azure Defender for SQL servers on machines should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos SQL Server en maquinas deben tener habilitado el Azure Defender."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6581d072-105e-4418-827f-bd446d56421b" $Description $policyName $scope $displayName "Y"

        # Azure Defender for SQL should be enabled for unprotected SQL Managed Instances
        # Effect AuditIFNotExists
        $policyName = "audit-azdf-asqlunprot"
        $displayName = "48) Azure Defender for SQL should be enabled for unprotected SQL Managed Instances"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL sin proteger deben tener habilitado el Azure Defender."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/abfb7388-5bf4-4ad7-ba99-2cd2f41cebb9" $Description $policyName $scope $displayName "Y"

        # Auditing on SQL server should be enabled
        # Effect AuditIFNotExists
        $policyName = "audit-audit-asql"
        $displayName = "49) Auditing on SQL server should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL debe tener habilitada la auditoria a nivel de servidor."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9" $Description $policyName $scope $displayName "Y"

        # SQL Auditing settings should have Action-Groups configured to capture critical activities
        # Effect AuditIFNotExists
        $policyName = "audit-auditcritical-asql"
        $displayName = "50) SQL Auditing settings should have Action-Groups configured to capture critical activities"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben capturar eventos criticos en sus logs de auditoria."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/7ff426e2-515f-405a-91c8-4f2333442eb5" $Description $policyName $scope $displayName "Y"

        # Vulnerability assessment should be enabled on SQL Managed Instance
        # Effect AuditIFNotExists
        $policyName = "audit-vulnass-asqlmi"
        $displayName = "51) Vulnerability assessment should be enabled on SQL Managed Instance"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL Managed deben tener habilitado el analisis de vulnerabilidades."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1b7aa243-30e4-4c9e-bca8-d0d3022b634a" $Description $policyName $scope $displayName "Y"

        # Vulnerability assessment should be enabled on your SQL servers
        # Effect AuditIFNotExists
        $policyName = "audit-vulnass-asql"
        $displayName = "52) Vulnerability assessment should be enabled on your SQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener habilitado el analisis de vulnerabilidades."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ef2a8f2a-b3d9-49cd-a8a8-9a3aaaf647d9" $Description $policyName $scope $displayName "Y"

        # Vulnerability Assessment settings for SQL server should contain an email address to receive scan reports
        # Effect AuditIFNotExists
        $policyName = "audit-vulnmail-asql"
        $displayName = "53) Vulnerability Assessment settings for SQL server should contain an email address to receive scan reports"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener configurada una direccion de correo para el envio de los analisis de vulnerabilidades."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/057d6cfe-9c4f-4a6d-bc60-14420ea1f1a9" $Description $policyName $scope $displayName "Y"
        
        # SQL servers on machines should have vulnerability findings resolved
        # Effect AuditIFNotExists
        $policyName = "audit-vulnresolmach-asql"
        $displayName = "54) SQL servers on machines should have vulnerability findings resolved"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL en maquinas deben tener solucionadas las vulnerabilidades reportadas por el Defender For Azure SQL Databases."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6ba6d016-e7c3-4842-b8f2-4992ebc0d72d" $Description $policyName $scope $displayName "Y"

        # SQL databases should have vulnerability findings resolved
        # Effect AuditIFNotExists
        $policyName = "audit-vulnresolved-asql"
        $displayName = "55) SQL databases should have vulnerability findings resolved"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener solucionadas las vulnerabilidades reportadas por el Defender For Azure SQL Databases."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/feedbf84-6b99-488c-acc2-71c829aa5ffc" $Description $policyName $scope $displayName "Y"

        # Event Hub Namespaces should disable public network access 
        # Effect DENY
        $policyName = "deny-publicaccess-ehub"
        $displayName = "56) Event Hub Namespaces should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure Event Hub namespaces deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0602787f-9896-402a-a6e1-39ee63ee435e" $Description $policyName $scope $displayName "Y" "Deny"
        
        # All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace
        # Effect DENY
        $policyName = "deny-authrules-sbus"
        $displayName = "57) All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las reglas de autorizacion excepto RootManageSharedAccessKey deben ser removidas del namespace del service bus."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a1817ec0-a368-432a-8057-8371e17ac6ee" $Description $policyName $scope $displayName "Y" "Deny"

        # Service Bus namespaces should have double encryption enabled
        # Effect DENY
        $policyName = "deny-doubleencrypt-sbus"
        $displayName = "58) Service Bus namespaces should have double encryption enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los namespace del service bus deben tener habilitado el doble cifrado."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ebaf4f25-a4e8-415f-86a8-42d9155bef0b" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Service Bus namespaces should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-sbus"
        $displayName = "59) Azure Service Bus namespaces should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Service Bus deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cfb11c26-f069-4c14-8e36-56c394dae5af" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Resource logs in Service Bus should be enabled
        # Effect AuditIfNotExist
        $policyName = "audit-reslogs-sbus"
        $displayName = "60) Resource logs in Service Bus should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Service bus deben retener los logs del recurso por un periodo de tiempo superior a 90 dias."
        $requireRetentionDays = "90"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f8d36e2f-389b-4ee4-898d-21aeb69a0f45" $Description $policyName $scope $displayName "Y" "AuditIfNotExists" $requireRetentionDays "requiredRetentionDays"

        # Service Bus Namespaces should disable public network access
        # Effect DENY
        $policyName = "deny-publicaccess-sbus"
        $displayName = "61) Service Bus Namespaces should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Service bus deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cbd11fd3-3002-4907-b6c8-579f0e700e13" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Service Bus namespaces should use private link
        # Effect AuditIFNotExists
        $policyName = "audit-plink-sbus"
        $displayName = "62) Azure Service Bus namespaces should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Service bus deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1c06e275-d63d-4540-b761-71f364c2111d" $Description $policyName $scope $displayName "Y"

        # Cognitive Services accounts should use a managed identity
        # Effect DENY
        $policyName = "deny-mid-cgntserv"
        $displayName = "63) Cognitive Services accounts should use a managed identity"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben usar una managed identity."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fe3fd216-4f83-4fc1-8984-2bbec80a3418" $Description $policyName $scope $displayName "Y" "Deny"

        # Cognitive Services accounts should disable public network access
        # Effect DENY
        $policyName = "deny-publicacc-cgntsrv"
        $displayName = "64) Cognitive Services accounts should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0725b4dd-7e76-479c-a735-68e7ee23d5ca" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Cognitive Search services should disable public network access
        # Effect DENY
        $policyName = "deny-public-cgntsrvsrch"
        $displayName = "65) Azure Cognitive Search services should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos de busqueda deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ee980b6d-0eca-4501-8d54-f6290fd512c3" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure Cognitive Search services should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlauth-cgntsrvsrch"
        $displayName = "66) Azure Cognitive Search services should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos de busqueda deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6300012e-e9a4-4649-b41f-a85f5c43be91" $Description $policyName $scope $displayName "Y" "Deny"
       
        # Cognitive Services accounts should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocauth-cgntserv"
        $displayName = "67) Cognitive Services accounts should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/71ef260a-8f18-47b7-abcb-62d0673d94dc" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Cognitive Search service should use a SKU that supports private link
        # Effect DENY
        $policyName = "deny-skuplink-cgntserv"
        $displayName = "68) Azure Cognitive Search service should use a SKU that supports private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben usar SKUs que soporten Private Link."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a049bf77-880b-470f-ba6d-9f21c530cf83" $Description $policyName $scope $displayName "Y" "Deny"

        # Cognitive Services accounts should restrict network access
        # Effect DENY
        $policyName = "deny-restnetacc-cgntserv"
        $displayName = "69) Cognitive Services accounts should restrict network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben restringir el acceso a nivel de red."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/037eea7a-bd0a-46c5-9a66-03aea78705d3" $Description $policyName $scope $displayName "Y" "Deny"

        # Log Analytics Workspaces should block non-Azure Active Directory based ingestion AuditIFNotExists
        # Effect DENY
        $policyName = "deny-nonaad-loganaw"
        $displayName = "70) Log Analytics Workspaces should block non-Azure Active Directory based ingestion"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios de log analytics deben bloquear las ingestas que no esten basadas en Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e15effd4-2278-4c65-a0da-4d6f6d1890e2" $Description $policyName $scope $displayName "Y"
 
        # Log Analytics workspaces should block log ingestion and querying from public networks AuditIFNotExists
        # Effect DENY
        $policyName = "deny-public-loganaw"
        $displayName = "71) Log Analytics workspaces should block log ingestion and querying from public networks"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios de log analytics deben bloquear las ingestas y consultas desde redes publicas."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6c53d030-cc64-46f0-906d-2bc061cd1334" $Description $policyName $scope $displayName "Y"

        # Azure Cosmos DB key based metadata write access should be disabled NO PARAMS
        $policyName = "audit-wrtkeyacc-cosmos"
        $displayName = "72) Azure Cosmos DB key based metadata write access should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben deshabilitar el acceso de escritura basado en llaves."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4750c32b-89c0-46af-bfcb-2e4541a818d5" $Description $policyName $scope $displayName "Y"

        # Microsoft Defender for Azure Cosmos DB should be enabled
        # Effect AuditIFNotExists
        $policyName = "audit-azdf-cosmos"
        $displayName = "73) Microsoft Defender for Azure Cosmos DB should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben tener habilitado Azure Defender"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/adbe85b5-83e6-4350-ab58-bf3a4f736e5e" $Description $policyName $scope $displayName "Y"

        # Cosmos DB database accounts should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-cosmos"
        $displayName = "74) Cosmos DB database accounts should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5450f5bd-9c72-4390-a9c4-a7aba4edfdd2" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure Cosmos DB should disable public network access
        # Effect DENY
        $policyName = "deny-publicaccess-cosmos"
        $displayName = "75) Azure Cosmos DB should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/797b37f7-06b8-444c-b1ad-fc62867f335a" $Description $policyName $scope $displayName "Y" "Deny"

        # CosmosDB accounts should use private link
        # Effect Audit
        $policyName = "audit-plink-cosmos"
        $displayName = "76) CosmosDB accounts should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben estar conectadaas a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/58440f8a-10c5-4151-bdce-dfbaad4a20b7" $Description $policyName $scope $displayName "Y"

        # API Management subscriptions should not be scoped at the All API scope
        # Effect DENY
        $policyName = "deny-allapiscope-apimgm"
        $displayName = "77) API Management subscriptions should not be scoped at the All API scope"
        $Description = "Para cumplir la linea base de seguridad de Azure las suscripciones del API Management no deben usar el scope All API"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3aa03346-d8c5-4994-a5bc-7652c2a2aef1" $Description $policyName $scope $displayName "Y" "Deny"

        # API Management minimum API version should be set to 2019-12-01 or higher
        # Effect DENY
        $policyName = "deny-api20191201-apimgm"
        $displayName = "78) API Management minimum API version should be set to 2019-12-01 or higher"
        $Description = "Para cumplir la linea base de seguridad de Azure la version minima de API debe ser 2019-12-01"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/549814b6-3212-4203-bdc8-1548d342fb67" $Description $policyName $scope $displayName "Y" "Deny"

        # API Management service should use a SKU that supports virtual networks
        # Effect DENY
        $policyName = "deny-skuvnet-apimgm"
        $displayName = "79) API Management service should use a SKU that supports virtual networks"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management deben usar SKUs que soporten VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/73ef9241-5d81-4cd4-b483-8443d1730fe5" $Description $policyName $scope $displayName "Y" "Deny"

        # API Management calls to API backends should not bypass certificate thumbprint or name validation
        # Effect DENY
        $policyName = "deny-bypasscrt-apimgm"
        $displayName = "80) API Management calls to API backends should not bypass certificate thumbprint or name validation"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management no deben saltar la validacion de nombres y de firmas de certificados."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/92bb331d-ac71-416a-8c91-02f2cb734ce4" $Description $policyName $scope $displayName "Y" "Deny"

        # API Management direct API Management endpoint should not be enabled
        # Effect DENY
        $policyName = "deny-directendp-apimgm"
        $displayName = "81) API Management direct API Management endpoint should not be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management no deben tener habilitado el endpoint directo."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b741306c-968e-4b67-b916-5675e5c709f4" $Description $policyName $scope $displayName "Y" "Deny"

        # API Management calls to API backends should be authenticated
        # Effect DENY
        $policyName = "deny-authbackend-apimgm"
        $displayName = "82) API Management calls to API backends should be authenticated"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management deben autenticarse ante los backend."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c15dcc82-b93c-4dcb-9332-fbf121685b54" $Description $policyName $scope $displayName "Y" "Deny"

        # API Management APIs should use encrypted protocols only
        # Effect DENY
        $policyName = "deny-encproto-apimgm"
        $displayName = "83) API Management APIs should use encrypted protocols only"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management solo deben usar protocolos con cifrado."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ee7495e7-3ba7-40b6-bfee-c29e22cc75d4" $Description $policyName $scope $displayName "Y" "Deny"

        # API Management Named Values secrets should be stored in Azure KeyVault
        # Effect DENY
        $policyName = "deny-kevynamval-apimgm"
        $displayName = "84) API Management Named Values secrets should be stored in Azure KeyVault"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management named values deben estar almacenados en un Key Vault."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f1cc7827-022c-473e-836e-5a51cae0b249" $Description $policyName $scope $displayName "Y" "Deny"

        # Public network access should be disabled for MySQL servers
        # Effect DENY
        $policyName = "deny-publicaccess-mysql"
        $displayName = "85) Public network access should be disabled for MySQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL deben tener desahabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/d9844e8a-1437-4aeb-a32c-0c992f056095" $Description $policyName $scope $displayName "Y" "Deny"

        # Infrastructure encryption should be enabled for Azure Database for MySQL servers
        # Effect DENY
        $policyName = "deny-infraenc-mysql"
        $displayName = "86) Infrastructure encryption should be enabled for Azure Database for MySQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL deben tener cifrado a nivel de infraestructura"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3a58212a-c829-4f13-9872-6371df2fd0b4" $Description $policyName $scope $displayName "Y" "Deny"

        # Private endpoint should be enabled for MySQL servers
        # Effect AuditIFNotExists
        $policyName = "audit-pendpoint-mysql"
        $displayName = "87) Private endpoint should be enabled for MySQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL deben estar conectadas a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/7595c971-233d-4bcf-bd18-596129188c49" $Description $policyName $scope $displayName "Y"

        # Public network access should be disabled for MySQL flexible servers
        # Effect DENY
        $policyName = "deny-public-mysqlflex"
        $displayName = "88) Public network access should be disabled for MySQL flexible servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL flexibles deben tener desahabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c9299215-ae47-4f50-9c54-8a392f68a052" $Description $policyName $scope $displayName "Y" "Deny"

        # Enforce SSL connection should be enabled for MySQL database servers
        # Effect Audit
        $policyName = "audit-ssl-mysql"
        $displayName = "89) Enforce SSL connection should be enabled for MySQL database servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL deben utilizar cifrado en transporte"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e802a67a-daf5-4436-9ea6-f6d821dd0c5d" $Description $policyName $scope $displayName "Y"

        # Public network access should be disabled for MariaDB servers
        # Effect DENY
        $policyName = "deny-publicacc-mariadb"
        $displayName = "90) Public network access should be disabled for MariaDB servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MariaDB deben tener desahabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fdccbe47-f3e3-4213-ad5d-ea459b2fa077" $Description $policyName $scope $displayName "Y" "Deny"

        # Private endpoint should be enabled for MariaDB servers
        # Effect AuditIFNotExists
        $policyName = "audit-pendpoint-mariadb"
        $displayName = "91) Private endpoint should be enabled for MariaDB servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MariaDB deben estar conectadas a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0a1302fb-a631-4106-9753-f3d494733990" $Description $policyName $scope $displayName "Y" 
        
        # Bot Service should have public network access disabled
        # Effect DENY
        $policyName = "deny-publicaccess-bots"
        $displayName = "92) Bot Service should have public network access disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Bot Service deben tener desahabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5e8168db-69e3-4beb-9822-57cb59202a9d" $Description $policyName $scope $displayName "Y" "Deny"

        # Bot Service endpoint should be a valid HTTPS URI
        # Effect DENY
        $policyName = "deny-validURI-bots"
        $displayName = "93) Bot Service endpoint should be a valid HTTPS URI"
        $Description = "Para cumplir la linea base de seguridad de azure los Azure Bot Service deben utilizar https"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6164527b-e1ee-4882-8673-572f425f5e0a" $Description $policyName $scope $displayName "Y" "Deny"

        # Bot Service resources should use private link
        # Effect Audit
        $policyName = "audit-plink-bots"
        $displayName = "94) BotService resources should use private link"
        $Description = "Para cumplir la linea base de seguridad de azure los Azure Bot Service deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ad5621d6-a877-4407-aa93-a950b428315e" $Description $policyName $scope $displayName "Y" 
        
        # Bot Service should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-bots"
        $displayName = "95) Bot Service should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de azure los Azure Bot Service deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ffea632e-4e3a-4424-bf78-10e179bb2e1a" $Description $policyName $scope $displayName "Y" "Deny"

        # Machine Learning computes should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-mlw"
        $displayName = "96) Machine Learning computes should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e96a9a5f-07ca-471b-9bc5-6a0f33cbd68f" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Machine Learning workspaces should disable public network access
        # Effect DENY
        $policyName = "deny-publicaccess-mlw"
        $displayName = "97) Azure Machine Learning workspaces should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/438c38d2-3772-465a-a9cc-7a6666a275ce" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure Machine Learning workspaces should use private link
        # Effect Audit
        $policyName = "deny-plink-mlw"
        $displayName = "98) Azure Machine Learning workspaces should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/40cec1dd-a100-4920-b15b-3024fe8901ab" $Description $policyName $scope $displayName "Y"

        # Resource logs in Azure Machine Learning workspace should be enabled
        # Effect Audit
        $policyName = "audit-reslogs-mlw"
        $displayName = "99) Resource logs in Azure Machine Learning workspace should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben retener los logs del recurso por un periodo de tiempo superior a 90 dias."
        $requireRetentionDays = "90"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/afe0c3be-ba3b-4544-ba52-0c99672a8ad6" $Description $policyName $scope $displayName "Y" "AuditIfNotExists" $requireRetentionDays "requiredRetentionDays"
       
        # Azure Event Grid topics should disable public network access
        # Effect DENY
        $policyName = "audit-pubaccess-egridtop"
        $displayName = "100) Azure Event Grid topics should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Topics deben deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1adadefe-5f21-44f7-b931-a59b54ccdb45" $Description $policyName $scope $displayName "Y" "Deny"
     
        # Azure Event Grid topics should use private link
        # Effect Audit
        $policyName = "audit-plink-egridtop"
        $displayName = "101) Azure Event Grid topics should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4b90e17e-8448-49db-875e-bd83fb6f804f" $Description $policyName $scope $displayName "Y"
       
        # Azure Event Grid topics should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-egridtop"
        $displayName = "102) Azure Event Grid topics should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Topics deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ae9fb87f-8a17-4428-94a4-8135d431055c" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Event Grid domains should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-egriddom"
        $displayName = "103) Azure Event Grid domains should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Domains deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8bfadddb-ee1c-4639-8911-a38cb8e0b3bd" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Event Grid domains should use private link
        # Effect Audit
        $policyName = "audit-plink-egriddom"
        $displayName = "104) Azure Event Grid domains should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Domains deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/9830b652-8523-49cc-b1b3-e17dce1127ca" $Description $policyName $scope $displayName "Y"

        # Azure Event Grid domains should disable public network access
        # Effect DENY
        $policyName = "audit-pubaccess-egriddom"
        $displayName = "105) Azure Event Grid domains should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Domains deben deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f8f774be-6aee-492a-9e29-486ef81f3a68" $Description $policyName $scope $displayName "Y" "Deny"
    
        # Azure Event Grid partner namespaces should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlauth-egridpnmsp"
        $displayName = "106) Azure Event Grid partner namespaces should have local authentication methods disabled "
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid partner namespaces deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8632b003-3545-4b29-85e6-b2b96773df1e" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Subnets should be associated with a Network Security Group
        # Effect AuditIfNotExist
        $policyName = "audit-sbnet-nsg"
        $displayName = "107) Subnets should be associated with a Network Security Group"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las subredes deben estar asociadas a un Network Security Group con reglas especificas."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e71308d3-144b-4262-b144-efdc3cc90517" $Description $policyName $scope $displayName "Y"

        # Flow logs should be configured for every network security group
        # Effect Audit                                                                
        $policyName = "audit-flowlogs-nsg"
        $displayName = "108) Flow logs should be configured for every network security group"
        $Description = "Para cumplir la linea base de seguridad de Azure los Network Security Group deben tener habilitador los logs."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/27960feb-a23c-4577-8d36-ef8b5f35e0be" $Description $policyName $scope $displayName "Y"

        # Gateway subnets should not be configured with a network security group NO PARAMETER
        $policyName = "audit-gwsbnet-nsg"
        $displayName = "109) Gateway subnets should not be configured with a network security group"
        $Description = "Para cumplir la linea base de seguridad de las Gateway subnets no deben tener un Network Security Group."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/35f9c03a-cc27-418e-9c0c-539ff999d010" $Description $policyName $scope $displayName "Y"

        # Azure Event Hub namespaces should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-ehub"
        $displayName = "110) Azure Event Hub namespaces should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de los Event Hub namespaces deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5d4e3c65-4873-47be-94f3-6f8b953a3598" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Event Hub namespaces should have double encryption enabled
        # Effect DENY
        $policyName = "deny-doubleencrypt-ehub"
        $displayName = "111) Event Hub namespaces should have double encryption enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Hub namespaces deben tener habilitado el doble cifrado."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/836cd60e-87f3-4e6a-a27c-29d687f01a4c" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Resource logs in Event Hub should be enabled
        # Effect AuditIFNotExists
        $policyName = "audit-reslogs-ehub"
        $displayName = "112) Resource logs in Event Hub should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Hub deben retener los logs del recurso por un periodo de tiempo superior a 90 dias."
        $requireRetentionDays = "90"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/83a214f7-d01a-484b-91a9-ed54470c9a6a" $Description $policyName $scope $displayName "Y" "AuditIfNotExists" $requireRetentionDays "requiredRetentionDays"
        
        # All authorization rules except RootManageSharedAccessKey should be removed from Event Hub namespace
        # Effect DENY
        $policyName = "deny-authrules-ehub"
        $displayName = "113) All authorization rules except RootManageSharedAccessKey should be removed from Event Hub namespace"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las reglas de autorizacion excepto RootManageSharedAccessKey deben ser removidas del namespace del event hub."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b278e460-7cfc-4451-8294-cccc40a940d7" $Description $policyName $scope $displayName "Y" "Deny"

        # Event Hub namespaces should use private link
        # Effect AuditIFNotExists
        $policyName = "audit-plink-ehub"
        $displayName = "114) Event Hub namespaces should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Hub namespaces deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b8564268-eb4a-4337-89be-a19db070c59d" $Description $policyName $scope $displayName "Y"

        # Azure Databricks Workspaces should disable public network access
        # Effect DENY
        $policyName = "deny-pubaccess-dtbrcks"
        $displayName = "115) Azure Databricks Workspaces should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Databricks Workspaces deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0e7849de-b939-4c50-ab48-fc6b0f5eeba2" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Databricks Clusters should disable public IP
        # Effect DENY
        $policyName = "deny-pubaccess-dnclus"
        $displayName = "116) Azure Databricks Clusters should disable public IP"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster que hacen parte de Databricks Workspaces deben tener deshabilitado el direccionamiento IP publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/51c1490f-3319-459c-bbbc-7f391bbed753" $Description $policyName $scope $displayName "Y" "Deny"

        # Resource logs in Azure Databricks Workspace should be enabled
        # Effect AuditIFNotExists
        $policyName = "audit-reslogs-dtbrcks"
        $displayName = "117) Resource logs in Azure Databricks Workspace should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Databricks Workspace deben retener los logs del recurso por un periodo de tiempo superior a 90 dias."
        $requireRetentionDays = "90"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/138ff14d-b687-4faa-a81c-898c91a87fa2" $Description $policyName $scope $displayName "Y" "AuditIfNotExists" $requireRetentionDays "requiredRetentionDays"

        # Azure Synapse workspaces should disable public network access
        # Effect DENY
        $policyName = "deny-publicaccess-synps"
        $displayName = "118) Azure Synapse workspaces should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/38d8df46-cf4e-4073-8e03-48c24b29de0d" $Description $policyName $scope $displayName "Y" "Deny"

        # Synapse managed private endpoints should only connect to resources in approved Azure Active Directory tenants
        # Effect DENY
        $policyName = "deny-aprovtenantid-synps"
        $displayName = "119) Synapse managed private endpoints should only connect to resources in approved Azure Active Directory tenants"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace solo se deben conectar a Tenants previamente aprobados."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3a003702-13d2-4679-941b-937e58c443f0" $Description $policyName $scope $displayName "Y" "Deny" @($TenantId) "allowedTenantIds"

        # Azure Synapse workspaces should allow outbound data traffic only to approved targets
        # Effect DENY
        $policyName = "deny-aprovoutbound-synps"
        $displayName = "120) Azure Synapse workspaces should allow outbound data traffic only to approved targets"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace solo se deben permitir el trafico de salida a destinos previamente aprobados."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3484ce98-c0c5-4c83-994b-c5ac24785218" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Synapse Workspace SQL Server should be running TLS version 1.2 or newer
        # Effect DENY
        $policyName = "deny-tls12-synps"
        $displayName = "121) Azure Synapse Workspace SQL Server should be running TLS version 1.2 or newer"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben usar la ultima version disponible de TLS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cb3738a6-82a2-4a18-b87b-15217b9deff4" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Synapse Analytics dedicated SQL pools should enable encryption
        # Effect AuditIFNotExists
        $policyName = "audit-tde-synps"
        $displayName = "122) Azure Synapse Analytics dedicated SQL pools should enable encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben tener habilitado el cifrado en reposo."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cfaf0007-99c7-4b01-b36b-4048872ac978" $Description $policyName $scope $displayName "Y"

        # Microsoft Defender for SQL should be enabled for unprotected Synapse workspaces
        # Effect AuditIFNotExists
        $policyName = "audit-azdf-synps"
        $displayName = "123) Microsoft Defender for SQL should be enabled for unprotected Synapse workspaces"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben tener habilitado Azure Defender"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/d31e5c31-63b2-4f12-887b-e49456834fa1" $Description $policyName $scope $displayName "Y"

        # Synapse Workspaces should use only Azure Active Directory identities for authentication
        # Effect DENY
        $policyName = "deny-aadauth-synps"
        $displayName = "124) Synapse Workspaces should use only Azure Active Directory identities for authentication"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben implementar Autenticacion de Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/2158ddbe-fefa-408e-b43f-d4faef8ff3b8" $Description $policyName $scope $displayName "Y" "Deny"

        # Auditing on Synapse workspace should be enabled
        # Effect AuditIFNotExists
        $policyName = "audit-audit-synps"
        $displayName = "125) Auditing on Synapse workspace should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben tener habilitada la auditoria a nivel de servidor."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e04e5000-cd89-451d-bb21-a14d24ff9c73" $Description $policyName $scope $displayName "Y"

        # Synapse workspace auditing settings should have action groups configured to capture critical activities
        # Effect AuditIFNotExists
        $policyName = "audit-auditcrit-synps"
        $displayName = "126) Synapse workspace auditing settings should have action groups configured to capture critical activitie"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben capturar eventos criticos en sus logs de auditoria."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/2b18f286-371e-4b80-9887-04759970c0d3" $Description $policyName $scope $displayName "Y"

        # Vulnerability assessment should be enabled on your Synapse workspaces
        # Effect AuditIFNotExists
        $policyName = "audit-vulnass-synps"
        $displayName = "127) Vulnerability assessment should be enabled on your Synapse workspaces"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben tener habilitado el analisis de vulnerabilidades."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0049a6b3-a662-4f3e-8635-39cf44ace45a" $Description $policyName $scope $displayName "Y"

        # Synapse workspaces with SQL auditing to storage account destination should be configured with 90 days retention or higher
        # Effect AuditIFNotExists
        $policyName = "audit-90retaudit-synps"
        $displayName = "128) Synapse workspaces with SQL auditing to storage account destination should be configured with 90 days retention or higher"
        $Description = "Para cumplir la linea base de seguridad de Azure los Synapse Workspace deben tener mas de 90 dias de retencion en los logs de auditoria."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/529ea018-6afc-4ed4-95bd-7c9ee47b00bc" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # Only secure connections to your Azure Cache for Redis should be enabled
        # Effect DENY
        $policyName = "deny-https-redis"
        $displayName = "129) Only secure connections to your Azure Cache for Redis should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las redis cache solo deben aceptar conexiones seguras."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/22bee202-a82f-4305-9a2a-6d7f44d4dedb" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure Cache for Redis should disable public network access
        # Effect DENY
        $policyName = "deny-pubaccess-redis"
        $displayName = "130) Azure Cache for Redis should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las redis cache deben deshabilitar el acceso público."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/470baccb-7e51-4549-8b1a-3e5be069f663" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Cache for Redis should use private link
        # Effect AuditIfNotExist
        $policyName = "audit-plink-redis"
        $displayName = "131) Azure Cache for Redis should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure las redis cache deben estar conectadas a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/7803067c-7d34-46e3-8c79-0ca68fc4036d" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"
     
        # App Configuration should disable public network access
        # Effect DENY
        $policyName = "deny-pubaccess-appconf"
        $displayName = "132) App Configuration should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las app configuration deben deshabilitar el acceso público."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3d9f5e4c-9947-4579-9539-2a7695fbc187" $Description $policyName $scope $displayName "Y" "Deny"

        # App Configuration should use private link
        # Effect AuditIfNotExists
        $policyName = "audit-plink-appconf"
        $displayName = "133) App Configuration should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure las app configuration deben estar conectadas a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ca610c1d-041c-4332-9d88-7ed3094967c7" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # App Configuration stores should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-appconf"
        $displayName = "134) App Configuration stores should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las app configuration deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b08ab3ca-1062-4db3-8803-eec9cae605d6" $Description $policyName $scope $displayName "Y" "Deny"

        # App Configuration should use a SKU that supports private link
        # Effect DENY
        $policyName = "deny-skuvnet-appconf"
        $displayName = "135) App Configuration should use a SKU that supports private link"
        $Description = "Para cumplir la linea base de seguridad de Azure las app configuration deben usar SKUs que soporten Private Link."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/89c8a434-18f0-402c-8147-630a8dea54e0" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure SignalR Service should disable public network access
        # Effect DENY
        $policyName = "deny-pubaccess-signalr"
        $displayName = "136) Azure SignalR Service should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios signalR deben deshabilitar el acceso público."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/21a9766a-82a5-4747-abb5-650b6dbba6d0" $Description $policyName $scope $displayName "Y" "Deny"
    
        # Azure SignalR Service should use private link
        # Effect Audit
        $policyName = "audit-plink-signalr"
        $displayName = "137) Azure SignalR Service should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios signalR deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/2393d2cf-a342-44cd-a2e2-fe0188fd1234" $Description $policyName $scope $displayName "Y" "Audit"
    
        # Azure SignalR Service should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-signalr"
        $displayName = "138) Azure SignalR Service should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios signalR deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f70eecba-335d-4bbc-81d5-5b17b03d498f" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure SignalR Service should use a Private Link enabled SKU
        # Effect DENY
        $policyName = "deny-skuvnet-signalr"
        $displayName = "139) Azure SignalR Service should use a Private Link enabled SKU"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios signalR deben usar SKUs que soporten Private Link."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/464a1620-21b5-448d-8ce6-d4ac6d1bc49a" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure Web PubSub Service should use a SKU that supports private link
        # Effect DENY
        $policyName = "deny-skuvnet-pubsub"
        $displayName = "140) Azure Web PubSub Service should use a SKU that supports private link SKU"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios Web PubSub deben usar SKUs que soporten Private Link."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/82909236-25f3-46a6-841c-fe1020f95ae1" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Web PubSub Service should disable public network access
        # Effect DENY
        $policyName = "deny-pubcaccess-pubsub"
        $displayName = "141) Azure Web PubSub Service should disable public network access SKU"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios Web PubSub deben deshabilitar el acceso público."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/bf45113f-264e-4a87-88f9-29ac8a0aca6a" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Web PubSub Service should have local authentication methods disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-pubsub"
        $displayName = "142) Azure Web PubSub Service should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios Web PubSub deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b66ab71c-582d-4330-adfd-ac162e78691e" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure Web PubSub Service should use private link
        # Effect Audit
        $policyName = "audit-plink-pubsub"
        $displayName = "143) Azure Web PubSub Service should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios Web PubSub deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/eb907f70-7514-460d-92b3-a5ae93b4f917" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Monitor Private Link Scope should use private link
        # Effetc AuditIFNotExists
        $policyName = "audit-plink-ampls"
        $displayName = "144) Azure Monitor Private Link Scope should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios de Azure Monitor deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0fc55270-f8bf-4feb-b7b8-5e7e7eacc6a6" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # Azure Monitor Private Link Scope should block access to non private link resources
        # Effect DENY
        $policyName = "deny-pubaccess-ampls"
        $displayName = "145) Azure Monitor Private Link Scope should block access to non private link resources"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios de Azure Monitor deben deshabilitar el acceso público."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a499fed8-bcc8-4195-b154-641f14743757" $Description $policyName $scope $displayName "Y" "Audit"
        
        # Enable Rate Limit rule to protect against DDoS attacks on Azure Front Door WAF
        # Effect Deny
        $policyName = "deny-waflimit-frontdoor"
        $displayName = "146) Enable Rate Limit rule to protect against DDoS attacks on Azure Front Door WAF"
        $Description = "Para cumplir la linea base de seguridad de Azure los Front Door deben tener la habilitada la caracteristica de Rate Limit para evitar ataques DDoS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e52e8487-4a97-48ac-b3e6-1c3cef45d298" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure Web Application Firewall should be enabled for Azure Front Door entry-points
        # Effect DENY
        $policyName = "deny-waf-frontdoor"
        $displayName = "147) Azure Web Application Firewall should be enabled for Azure Front Door entry-points."
        $Description = "Para cumplir la linea base de seguridad de Azure los Front Door deben implementar un Web Application Firewall."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/055aa869-bc98-4af8-bafc-23f1ab6ffe2c" $Description $policyName $scope $displayName "Y" "Audit"
        
        # Web Application Firewall (WAF) should use the specified mode for Azure Front Door Service
        # Effect DENY
        $policyName = "deny-wafprev-frontdoor"
        $displayName = "148) Web Application Firewall (WAF) should use the specified mode for Azure Front Door Service."
        $Description = "Para cumplir la linea base de seguridad de Azure los Front Door deben implementar el modo prevencion en el Web Application Firewall."
        $modeRequeriment = "Prevention"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/425bea59-a659-4cbb-8d31-34499bd030b8" $Description $policyName $scope $displayName "Y" "Audit" $modeRequeriment "modeRequirement"
   
        # Azure Front Door Standard and Premium should be running minimum TLS version of 1.2
        # Effect DENY
        $policyName = "deny-tls12-frontdoor"
        $displayName = "149) Azure Front Door Standard and Premium should be running minimum TLS version of 1.2"
        $Description = "Para cumplir la linea base de seguridad de Azure los Front Door deben usar la ultima version disponible de TLS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/679da822-78a7-4eff-8fff-a899454a9970" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Secure private connectivity between Azure Front Door Premium and Azure Storage Blob, or Azure App Service
        # Effect DENY
        $policyName = "audit-plink-frontdoor"
        $displayName = "150) Secure private connectivity between Azure Front Door Premium and Azure Storage Blob, or Azure App Service"
        $Description = "Para cumplir la linea base de seguridad de Azure los Front Door deben conectarse a los recursos a través de una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/daba2cce-8326-4af3-b049-81a362da024d" $Description $policyName $scope $displayName "Y" "Audit"
      
        # Azure Front Door profiles should use Premium tier that supports managed WAF rules and private link
        # Effect DENY
        $policyName = "deny-premium-frontdoor"
        $displayName = "151) Azure Front Door profiles should use Premium tier that supports managed WAF rules and private link."
        $Description = "Para cumplir la linea base de seguridad de Azure los Front Door deben usar tiers que soporten WAF y VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/dfc212af-17ea-423a-9dcb-91e2cb2caa6b" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Data Explorer should use a SKU that supports private link
        # Effect DENY        
        $policyName = "deny-skuvnet-dataex"
        $displayName = "152) Azure Data Explorer should use a SKU that supports private link."
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Explorer deben usar SKUs que soporten Private Link."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1fec9658-933f-4b3e-bc95-913ed22d012b" $Description $policyName $scope $displayName "Y" "Deny"

        # Public network access on Azure Data Explorer should be disabled
        # Effect DENY        
        $policyName = "deny-pubaccess-dataex"
        $displayName = "153) Public network access on Azure Data Explorer should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Explorer deben deshabilitar el acceso público."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/43bc7be6-5e69-4b0d-a2bb-e815557ca673" $Description $policyName $scope $displayName "Y" "Deny"

        # Double encryption should be enabled on Azure Data Explorer
        # Effect DENY        
        $policyName = "deny-doubleencrypt-dtex"
        $displayName = "154) Double encryption should be enabled on Azure Data Explorer"
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Explorer deben tener habilitado el doble cifrado."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ec068d99-e9c7-401f-8cef-5bdde4e6ccf1" $Description $policyName $scope $displayName "Y" "Deny"

        #  Web Application Firewall (WAF) should be enabled for Application Gateway
        # Effect DENY        
        $policyName = "deny-waf-appgtwy"
        $displayName = "155) Web Application Firewall (WAF) should be enabled for Application Gateway"
        $Description = "Para cumplir la linea base de seguridad de Azure los Application Gateway deben tener habilitadas las caracteristicas de WAF."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/564feb30-bf6a-4854-b4bb-0d2d2d1e6c66" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Web Application Firewall on Azure Application Gateway should have request body inspection enabled
        # Effect DENY        
        $policyName = "deny-reqinsp-appgtwy"
        $displayName = "156) Azure Web Application Firewall on Azure Application Gateway should have request body inspection enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Application Gateway deben tener habilitada la inspeccion en el body de las peticiones."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ca85ef9a-741d-461d-8b7a-18c2da82c666" $Description $policyName $scope $displayName "Y" "Deny"

        # Web Application Firewall (WAF) should use the specified mode for Application Gateway
        # Effect DENY        
        $policyName = "deny-wafprev-appgtwy"
        $displayName = "157) Web Application Firewall (WAF) should use the specified mode for Application Gateway"
        $Description = "Para cumplir la linea base de seguridad de Azure los Application Gateway deben implementar el modo prevencion en el Web Application Firewall."
        $modeRequeriment = "Prevention"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/12430be1-6cc8-4527-a9a8-e3d38f250096" $Description $policyName $scope $displayName "Y" "Deny" $modeRequeriment "modeRequirement"

        # Web Application Firewall (WAF) should enable all firewall rules for Application Gateway
        # Effect DENY        
        $policyName = "deny-enablerules-appgtwy"
        $displayName = "158) Web Application Firewall (WAF) should enable all firewall rules for Application Gateway"
        $Description = "Para cumplir la linea base de seguridad de Azure los Application Gateway habilitar todas las reglas en el Web Application Firewall."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/632d3993-e2c0-44ea-a7db-2eca131f356d" $Description $policyName $scope $displayName "Y" "Deny"

        # Migrate WAF from WAF Config to WAF Policy on Application Gateway
        # Effect DENY        
        $policyName = "deny-wafpolicy-appgtwy"
        $displayName = "159) Migrate WAF from WAF Config to WAF Policy on Application Gateway"
        $Description = "Para cumplir la linea base de seguridad de Azure los Application Gateway deben migrarse a WAF Policy en el Web Application Firewall."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/882e19a6-996f-400e-a30f-c090887254f4" $Description $policyName $scope $displayName "Y" "Deny"

        # Container registries should have anonymous authentication disabled
        # Effect DENY
        $policyName = "deny-anonauth-acr"
        $displayName = "160) Container registries should have anonymous authentication disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben tener deshabilitada la autenticacion anonima."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/9f2dea28-e834-476c-99c5-3507b4728395" $Description $policyName $scope $displayName "Y" "Deny"
 
        # Container registry images should have vulnerability findings resolved
        # Effect AuditIfNotExists
        $policyName = "audit-novuln-acr"
        $displayName = "161) Container registry images should have vulnerability findings resolved"
        $Description = "Para cumplir la linea base de seguridad de Azure las imagenes en los Azure Container Registry deben tener remediadas las vulnerabilidades."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5f0f936f-2f01-4bf5-b6be-d423792fa562" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"
       
        # Public network access should be disabled for Container registries
        # Effect DENY
        $policyName = "deny-pubaccess-acr"
        $displayName = "162) Public network access should be disabled for Container registries"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben deshabilitar el acceso público."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0fdf0491-d080-4575-b627-ad0e843cba0f" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Container registries should have SKUs that support Private Links
        # Effect DENY
        $policyName = "deny-skuvnet-acr"
        $displayName = "163) Container registries should have SKUs that support Private Links"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben usar SKUs que soporten Private Link"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/bd560fc0-3c69-498a-ae9f-aa8eb7de0e13" $Description $policyName $scope $displayName "Y" "Deny"

        # Container registries should have exports disabled
        # Effect DENY
        $policyName = "deny-noexport-acr"
        $displayName = "164) Container registries should have exports disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben tener deshabilitados los export"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/524b0254-c285-4903-bee6-bb8126cde579" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure MySQL flexible server should have Microsoft Entra Only Authentication enabled 
        # EffectAuditIFNotExists
        $policyName = "audit-entauth-mysqlflex"
        $displayName = "165) Azure MySQL flexible server should have Microsoft Entra Only Authentication enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los MySQL flexible servers deben implementar unicamente Autenticacion de Microsoft Entra ID"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/40e85574-ef33-47e8-a854-7a65c7500560" $Description $policyName $scope $displayName "Y"
        
        # Container registries should have ARM audience token authentication disabled
        # Effect DENY
        $policyName = "deny-noarmaudtoken-acr"
        $displayName = "166) Container registries should have ARM audience token authentication disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben tener deshabilitado el token de audiencia ARM"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/42781ec6-6127-4c30-bdfa-fb423a0047d3" $Description $policyName $scope $displayName "Y" "Deny"

        # Container registries should have local admin account disabled
        # Effect DENY
        $policyName = "deny-dlocaladmin-acr"
        $displayName = "167) Container registries should have local admin account disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben tener deshabilitado el administrador local y en su lugar se deben usar cuentas de Azure Active Directory"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/dc921057-6b28-4fbe-9b83-f7bec05db6c2" $Description $policyName $scope $displayName "Y" "Deny"

        # Container registries should have repository scoped access token disabled
        # Effect DENY
        $policyName = "deny-noscopedtoken-acr"
        $displayName = "168) Container registries should have repository scoped access token disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben tener deshabilitado el token de acceso al repositorio y en su lugar se deben usar cuentas de Azure Active Directory"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ff05e24e-195c-447e-b322-5e90c9f9f366" $Description $policyName $scope $displayName "Y" "Deny"

        # Storage accounts should disable public network access
        # Effect DENY
        $policyName = "deny-netaccess-strg"
        $displayName = "169) Storage accounts should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las cuentas de storage deben tener deshabilitado el acceso publico y usar private endpoints."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b2982f36-99f2-4db5-8eff-283140c09693" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Storage accounts should use private link
        # Effect AuditIfNotExists
        $policyName = "audit-plink-strg"
        $displayName = "170) Storage accounts should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las cuentas de storage deben estar conectadas a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6edd7eda-6dd8-40f7-810d-67160c639cd9" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # App Configuration should use a customer-managed key
        # Effect DENY
        $policyName = "deny-byok-appconf"
        $displayName = "171) App Configuration should use a customer-managed key"
        $Description = "Para cumplir la linea base de seguridad de Azure y los controles CIS las app configuration deben utilizar el cifrado con llave de cliente (Customer Managed Key)."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/967a4b4b-2da9-43c1-b7d0-f98d0d74d0b1" $Description $policyName $scope $displayName "Y" "Audit"
       
        # Azure Backup should be enabled for Virtual Machines
        # Effect AuditIfNotExists
        $policyName = "audit-azbackup-vm"
        $displayName = "172) Azure Backup should be enabled for Virtual Machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales deben tener habilitado Azure Backup"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/013e242c-8828-4970-87b3-ab247555486d" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # Adaptive network hardening recommendations should be applied on internet facing virtual machines
        # Effect AuditIfNotExists
        $policyName = "audit-adaptnetwork-vm"
        $displayName = "173) Adaptive network hardening recommendations should be applied on internet facing virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales deben tener habilitado el adaptative networking con el fin de controlar el trafico de entrada y salida"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/08e6af2d-db70-460a-bfe9-d5bd474ba9d6" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # Virtual machines and virtual machine scale sets should have encryption at host enabled
        # Effect DENY
        $policyName = "audit-encrypthost-vm"
        $displayName = "174) Virtual machines and virtual machine scale sets should have encryption at host enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales deben implementar cifrado end to end usando encryption at host"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fc4d8e41-e223-45ea-9bf5-eada37891d87" $Description $policyName $scope $displayName "Y" "Audit"

        # [Preview]: vTPM should be enabled on supported virtual machines
        # Effect Audit
        $policyName = "audit-vtpm-vm"
        $displayName = "175) [Preview]: vTPM should be enabled on supported virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales deben habilitar las caracteristicas de vTPM"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1c30f9cd-b84c-49cc-aa2c-9288447cc3b3" $Description $policyName $scope $displayName "Y" "Audit"

        # [Preview]: Guest Attestation extension should be installed on supported Windows virtual machines
        # Effect AuditIfNotExists
        $policyName = "audit-guestattestwin-vm"
        $displayName = "176) [Preview]: Guest Attestation extension should be installed on supported Windows virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales Windows deben habilitar la extension Guest Attestation"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1cb4d9c2-f88f-4069-bee0-dba239a57b09" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"
        
        # Virtual machines should be migrated to new Azure Resource Manager resources
        # Effect DENY
        $policyName = "deny-azarm-vm"
        $displayName = "177) Virtual machines should be migrated to new Azure Resource Manager resources"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales deben migrarse a Azure Resource Manager para usar las caracteristicas de seguridad avanzada"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1d84d5fb-01f6-4d12-ba4f-4a26081d403d" $Description $policyName $scope $displayName "Y" "Audit"

        # Endpoint protection should be installed on your machines
        # Effect AuditIfNotExists
        $policyName = "deny-endpproc-vm"
        $displayName = "178) Endpoint protection should be installed on your machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales tener instalada una solución de protección de endpoint"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1f7c564c-0a90-4d44-b7e1-9d456cffaee8" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # A vulnerability assessment solution should be enabled on your virtual machines
        # Effect AuditIfNotExists
        $policyName = "audit-vulnass-vm"
        $displayName = "179) A vulnerability assessment solution should be enabled on your virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales tener instalada una solución de analisis de vulnerabilidades"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/501541f7-f7e7-4cd6-868c-4190fdad3ac9" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # [Preview]: Secure Boot should be enabled on supported Windows virtual machines
        # Effect Audit
        $policyName = "audit-secbootwin-vm"
        $displayName = "180) [Preview]: Secure Boot should be enabled on supported Windows virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales Windows deben tener habilitado el secure boot."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/97566dd7-78ae-4997-8b36-1c7bfe0d8121" $Description $policyName $scope $displayName "Y" "Audit"

        # [Preview]: Linux virtual machines should use Secure Boot
        # Effect AuditIfNotExists
        $policyName = "audit-secbootlin-vm"
        $displayName = "181) [Preview]: Linux virtual machines should use Secure Boot"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales Linux deben tener habilitado el secure boot."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b1bb3592-47b8-4150-8db0-bfdcc2c8965b" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # All network ports should be restricted on network security groups associated to your virtual machine
        # Effect AuditIfNotExist
        $policyName = "audit-nsgports-vm"
        $displayName = "182) All network ports should be restricted on network security groups associated to your virtual machine"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales deben tener restricciones de puertos en los Network Security Groups de acuerdo a las necesidades del negocio"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/9daedab3-fb2d-461e-b861-71790eead4f6" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # [Preview]: Azure Security agent should be installed on your Linux virtual machines
        # Effect AuditIfNotExist
        $policyName = "audit-secagentlin-vm"
        $displayName = "183) [Preview]: Azure Security agent should be installed on your Linux virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales Linux deben tener instalado el agente de seguridad de Azure"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e8794316-d918-4565-b57d-6b38a06381a0" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # [Preview]: Azure Security agent should be installed on your Windows virtual machines
        # Effect AuditIFNotExists
        $policyName = "audit-secagentwin-vm"
        $displayName = "184) [Preview]: Azure Security agent should be installed on your Windows virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales Windows deben tener instalado el agente de seguridad de Azure"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/bb2c6c6d-14bc-4443-bef3-c6be0adc6076" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # Non-internet-facing virtual machines should be protected with network security groups
        # Effect AuditIfNotExists
        $policyName = "audit-nointnet-vm"
        $displayName = "185) Non-internet-facing virtual machines should be protected with network security groups"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales no expuestas a internet deben tener Network Security Groups asociados ya sea a la tarjeta de red, a la subred que se conectan o ambos"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/bb91dfba-c30d-4263-9add-9c2384e659a6" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # Internet-facing virtual machines should be protected with network security groups
        # Effect AuditIfNotExists
        $policyName = "audit-intnet-vm"
        $displayName = "186) Internet-facing virtual machines should be protected with network security groups"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales expuestas a internet deben tener Network Security Groups asociados ya sea a la tarjeta de red, a la subred que se conectan o ambos"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f6de0be7-9a8a-4b8a-b349-43cf02d22f7c" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # IP Forwarding on your virtual machine should be disabled
        # Effect AuditIfNotExists
        $policyName = "audit-ipfwd-vm"
        $displayName = "187) IP Forwarding on your virtual machine should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales deben tener deshabilitada la funcionalidad de IP Forwarding"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/bd352bd5-2853-4985-bf0d-73806b4a5744" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # Virtual machines Guest Configuration extension should be deployed with system-assigned managed identity
        # Effect AuditIfNotExists
        $policyName = "audit-midguestext-vm"
        $displayName = "188) Virtual machines Guest Configuration extension should be deployed with system-assigned managed identity"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales deben tener desplegada la extension para configuracion Guest usando una system managed identity"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/d26f7642-7545-4e18-9b75-8c9bbdee3a9a" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # [Preview]: ChangeTracking extension should be installed on your Linux virtual machine
        # Effect AuditIfNotExists
        $policyName = "audit-chgtrckextlin-vm"
        $displayName = "189) [Preview]: ChangeTracking extension should be installed on your Linux virtual machine"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales Linux deben tener desplegada la extension ChangeTracking"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8893442c-e7cb-4637-bab8-299a5d4ed96a" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # [Preview]: ChangeTracking extension should be installed on your Windows virtual machine
        # Effect AuditIfNotExists
        $policyName = "audit-chgtrckextwin-vm"
        $displayName = "190) [Preview]: ChangeTracking extension should be installed on your Windows virtual machine"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales Windows deben tener desplegada la extension ChangeTracking"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/221aac80-54d8-484b-83d7-24f4feac2ce0" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"
        
        # [Preview]: Boot Diagnostics should be enabled on virtual machines
        # Effect Audit
        $policyName = "audit-bootdiag-vm"
        $displayName = "191) [Preview]: Boot Diagnostics should be enabled on virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales deben tener habilitados los diagnosticos de inicio"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fb97d6e1-5c98-4743-a439-23e0977bad9e" $Description $policyName $scope $displayName "Y" "Audit"

        # [Preview]: Linux virtual machines should use only signed and trusted boot components
        # Effect AuditIfNotExists
        $policyName = "audit-bootsigned-vm"
        $displayName = "192) [Preview]: Linux virtual machines should use only signed and trusted boot components"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales Linux solo deben utilizar componentes de inicio confiables y firmados"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/13a6c84f-49a5-410a-b5df-5b880c3fe009" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # Machines should be configured to periodically check for missing system updates
        # Effect Audit
        $policyName = "audit-checkupdates-vm"
        $displayName = "193) Machines should be configured to periodically check for missing system updates"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las maquinas virtuales Linux solo deben utilizar componentes de inicio confiables y firmados"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/bd876905-5b84-4f73-ab2d-2e7a7c4568d9" $Description $policyName $scope $displayName "Y" "Audit"

        # [Preview]: Azure Data Factory pipelines should only communicate with allowed domains
        # Effect DENY
        $policyName = "disable-domainnames-dtfy"
        $displayName = "194) [Preview]: Azure Data Factory pipelines should only communicate with allowed domains"
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Factory solo se pueden conectar a dominios previamente aprobados."
        $allowedDomainNamesArray =@("xm.com.co")
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3d02a511-74e5-4dab-a5fd-878704d4a61a" $Description $policyName $scope $displayName $null "Disabled" $allowedDomainNamesArray "allowedDomainNames"
        
        # Azure Kubernetes Service Private Clusters should be enabled 
        # Effect DENY
        $policyName = "deny-privclu-aks"
        $displayName = "195) Azure Kubernetes Service Private Clusters should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los AKS deben implementar los clusters en modo privado"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/040732e8-d947-40b8-95d6-854c95024bf8" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Service Clusters should enable node os auto-upgrade
        # Effect Audit
        $policyName = "audit-autoupgrnode-aks"
        $displayName = "196) Azure Kubernetes Service Clusters should enable node os auto-upgrade"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters de AKS deben tener el auto-upgrade hablitado en el sistema operativo de los nodos"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/04408ca5-aa10-42ce-8536-98955cdddd4c" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Policy Add-on for Kubernetes service (AKS) should be installed and enabled on your clusters 
        # Effect Audit
        $policyName = "audit-poladdon-aks"
        $displayName = "197) Azure Policy Add-on for Kubernetes service (AKS) should be installed and enabled on your clusters"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters AKS deben instalado el add-on de Azure Policy"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0a15ec92-a229-4763-bb14-0ea34a568f8d" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Service Clusters should disable Command Invoke
        # Effect Audit
        $policyName = "audit-dsblecommand-aks"
        $displayName = "198) Disable Command Invoke on Azure Kubernetes Service"
        $Description = "Para cumplir la linea base de seguridad de Azure los AKS deben tener deshabilitado el command invoke"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/89f2d532-c53c-4f8f-9afa-4927b1114a0d" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Service Clusters should enable workload identity Audit
        # Effect Audit
        $policyName = "audit-wrkldident-aks"
        $displayName = "199) Azure Kubernetes Service Clusters should enable workload identity"
        $Description = "Para cumplir la linea base de seguridad de Azure los AKS deben tener habilitada la workload identity para el acceso seguro desde los pods"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/2cc2e023-0dac-4046-875b-178f683929d5" $Description $policyName $scope $displayName "Y" "Audit"
        
        # Temp disks and cache for agent node pools in Azure Kubernetes Service clusters should be encrypted at host 
        # Effect DENY
        $policyName = "deny-encrypthost-aks"
        $displayName = "200) Temp disks and cache for agent node pools in Azure Kubernetes Service clusters should be encrypted at host"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters de AKS deben implementar cifrado end to end usando encryption at host"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/41425d9f-d1a5-499a-9932-f8ed8453932c" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Service Clusters should enable Azure Active Directory integration
        # Effect Audit
        $policyName = "audit-aadintegration-aks"
        $displayName = "201) Azure Kubernetes Service Clusters should enable Azure Active Directory integration"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters de AKS deben tener habilitada la integración con Azure Active Directory"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/450d2877-ebea-41e8-b00c-e286317d21bf" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Service Clusters should have local authentication methods disabled 
        # Effect DENY
        $policyName = "deny-dlocalauth-aks"
        $displayName = "202) Azure Kubernetes Service Clusters should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters de AKS deben tener habilitada la integración con Azure Active Directory"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/993c2fcd-2b29-49d2-9eb0-df2c3a730c32" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Service Clusters should enable Image Cleaner
        # Effect Audit
        $policyName = "audit-imgcleaner-aks"
        $displayName = "203) Azure Kubernetes Service Clusters should enable Image Cleaner"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters de AKS deben tener habilitado el image cleaner que elimina de forma automatica imagenes vulnerables"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/af3c26b2-6fad-493e-9236-9c68928516ab" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Clusters should enable Container Storage Interface(CSI)
        # Effect Audit
        $policyName = "audit-strgcsi-aks"
        $displayName = "204) Azure Kubernetes Clusters should enable Container Storage Interface(CSI)"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters de AKS deben tener habilitado CSI (Container Storage Interface)"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c5110b6e-5272-4989-9935-59ad06fdf341" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Service Clusters should use managed identities
        # Effect Audit
        $policyName = "audit-mngid-aks"
        $displayName = "205) Azure Kubernetes Service Clusters should use managed identities"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters de AKS deben usar una managed identity"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/da6e2401-19da-4532-9141-fb8fbde08431" $Description $policyName $scope $displayName "Y" "Audit"

        # Kubernetes clusters should be accessible only over HTTPS 
        # Effect DENY
        $policyName = "deny-https-aks"
        $displayName = "206) Kubernetes clusters should be accessible only over HTTPS"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes solo se deben acceder sobre HTTPS"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes clusters should not allow container privilege escalation
        # Effect DENY
        $policyName = "deny-privescala-aks"
        $displayName = "207) Kubernetes clusters should not allow container privilege escalation"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes no deben permitir el escalamiento de privilegios."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1c6e92c9-99f0-4e55-9cf2-0c234dc48f99" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes clusters should disable automounting API credentials
        # Effect DENY
        $policyName = "deny-automountapi-aks"
        $displayName = "208) Kubernetes clusters should disable automounting API credentials"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes deben tener deshabilitado em automontaje de las credenciales de API."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/423dd1ba-798e-40e4-9c4d-b6902674b423" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes cluster containers should not share host process ID or host IPC namespace
        #Effect DENY
        $policyName = "deny-hostIDIPC-aks"
        $displayName = "209) Kubernetes cluster containers should not share host process ID or host IPC namespace"
        $Description = "Para cumplir la linea base de seguridad de Azure los pods de los cluster de Azure Kubernetes no deben exponer los process ID de host o el namespace IPC del host."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/47a1ee2f-2a2a-4576-bf2a-e0e36709c2b8" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes cluster Windows containers should not run as ContainerAdministrator
        # Effect DENY
        $policyName = "deny-notrunadmin-aks"
        $displayName = "210) Kubernetes cluster Windows containers should not run as ContainerAdministrator"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes no deben ejecutarse como ContaiderAdministrator"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5485eac0-7e8f-4964-998b-a44f4f0c1e75" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes cluster pods should only use approved host network and port range
        #Effect DENY
        $policyName = "deny-approvednetport-aks"
        $displayName = "211) Kubernetes cluster pods should only use approved host network and port range"
        $Description = "Para cumplir la linea base de seguridad de Azure los pods de los cluster de Azure Kubernetes solo deben usar redes y puertos aprobados."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/82985f06-dc18-4a48-bc1c-b9f4f0098cfe" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes cluster should not allow privileged containers
        # Effect DENY
        $policyName = "deny-noprivcontainers-aks"
        $displayName = "212) Kubernetes cluster should not allow privileged containers"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes no deben usar contenedores privilegiados."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/95edb821-ddaf-4404-9732-666045e056b4" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes clusters should not use the default namespace
        # EFfect DENY
        $policyName = "deny-defnamespace-aks"
        $displayName = "213) Kubernetes clusters should not use the default namespace"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes no deben usar el namespace por omision"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/9f061a12-e40d-4183-a00e-171812443373" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes clusters should not grant CAP_SYS_ADMIN security capabilities
        # Effect DENY
        $policyName = "deny-cpapsyadmin-aks"
        $displayName = "214) Kubernetes clusters should not grant CAP_SYS_ADMIN security capabilities"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes no deben ejecutarse bajo el contexto de seguridad CAP_SYS_ADMIN."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/d2e7ea85-6b44-4317-a0be-1b951587f626" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes cluster containers should run with a read only root file system
        #Effect DENY
        $policyName = "deny-norootexec-aks"
        $displayName = "215) Kubernetes cluster containers should run with a read only root file system"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes deben ejecutarse con un filesystem root de solo lectura."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/df49d893-a74c-421d-bc95-c663042e5b80" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes cluster containers should only use allowed ProcMountType
        # Effect DENY
        $policyName = "deny-procmountty-aks"
        $displayName = "216) Kubernetes cluster containers should only use allowed ProcMountType"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes solo deben permitir ProcMountType en los contenedores."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f85eb0dd-92ee-40e9-8a76-db25a507d6d3" $Description $policyName $scope $displayName $null "Audit"

        # Kubernetes cluster containers should only use allowed images
        # Effect DENY 
        $policyName = "deny-allowimg-aks"
        $allowedContainerImagesRegex = "^([^\/]+\.azurecr\.io|registry\.io)\/.+$"
        $displayName = "217) Kubernetes cluster containers should only use allowed images"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes solo deben permitir el uso de imagenes permitidas."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/febd0533-8e55-448f-b837-bd0e06f16469" $Description $policyName $scope $displayName $null "Audit" $allowedContainerImagesRegex "allowedContainerImagesRegex"

        # Azure Kubernetes Service Private Clusters should be enabled
        # Effect DENY
        $policyName = "deny-privcluster-aks"
        $displayName = "218) Azure Kubernetes Service Private Clusters should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes deben ser privados."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/040732e8-d947-40b8-95d6-854c95024bf8" $Description $policyName $scope $displayName "Y" "Audit"

        # Authorized IP ranges should be defined on Kubernetes Services
        # Effect Audit
        $policyName = "audit-ipapiaccess-aks"
        $displayName = "219) Authorized IP ranges should be defined on Kubernetes Services"
        $Description = "Para cumplir la linea base de seguridad de Azure el API de Azure Kubernetes solo debe recibir peticiones desde direcciones IP autorizadas"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0e246bcf-5f6f-4f87-bc6f-775d4712c7ea" $Description $policyName $scope $displayName "Y"

        # [Preview]: Managed Identity Federated Credentials from Azure Kubernetes should be from trusted sources
        # EFfect Audit
        $policyName = "audit-federauth-aks"
        $displayName = "220) [Preview]: Managed Identity Federated Credentials from Azure Kubernetes should be from trusted sources"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Kubernetes Services solo deben aceptar credenciales desde fuentes federadas de confianza"
        $TenantArray =@($TenantId)
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ae62c456-33de-4dc8-b100-7ce9028a7d99" $Description $policyName $scope $displayName "Y" "Audit" $TenantArray "allowedTenants"

        # Kubernetes Services should be upgraded to a non-vulnerable Kubernetes version
        # Effect Audit
        $policyName = "audit-novuln-aks"
        $displayName = "221) Kubernetes Services should be upgraded to a non-vulnerable Kubernetes version"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios de Azure Kubernetes deben actualizarse a versiones no vulnerables."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fb893a29-21bb-418c-a157-e99480ec364c" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Kubernetes Clusters should enable Key Management Service (KMS)
        # Effect Audit
        $policyName = "audit-kms-aks"
        $displayName = "222) Azure Kubernetes Clusters should enable Key Management Service (KMS)"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Kubernetes  Services deben tener habilitado el servicio de administracion de llaves (KMS)"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/dbbdc317-9734-4dd8-9074-993b29c69008" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure API Management platform version should be stv2
        # EFfect DENY
        $policyName = "deny-stv2-apim"
        $displayName = "223) Azure API Management platform version should be stv2"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure API Management deben utilizar la version de plataforma stv2"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1dc2fc00-2245-4143-99f4-874c937f13ef" $Description $policyName $scope $displayName "Y" "Deny"

        # Microsoft Defender for APIs should be enabled
        # Effect AuditIfNotExists
        $policyName = "audit-azdf-apis"
        $displayName = "224) Microsoft Defender for APIs should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure API Management deben utilizar Microsoft Defender For APIs"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/7926a6d1-b268-4586-8197-e8ae90c877d7" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # API endpoints in Azure API Management should be authenticated
        # Effect AuditIfNotExists
        $policyName = "audit-authendpoint-apim"
        $displayName = "225) API endpoints in Azure API Management should be authenticated"
        $Description = "Para cumplir la linea base de seguridad de Azure los endpoints en los Azure API Management deben utilizar autenticacion"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8ac833bd-f505-48d5-887e-c993a1d3eea0" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"

        # API Management should have username and password authentication disabled
        # Effect Audit
        $policyName = "audit-dlocalauth-apim"
        $displayName = "226) API Management should have username and password authentication disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure API Managementd deben tener deshabilitada la autenticacion local y en su lugar se deben usar cuentas de Azure Active Directory"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ffe25541-3853-4f4e-b71d-064422294b11" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Container Instance container group should deploy into a virtual network
        # Effect DENY
        $policyName = "deny-vnet-azcontainerinstance"
        $displayName = "227) Azure Container Instance container group should deploy into a virtual network"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Instances se deben desplegar en una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8af8f826-edcb-4178-b35f-851ea6fea615" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Event Grid namespaces should disable public network access
        # Effect DENY
        $policyName = "deny-pubaccess-egridnam"
        $displayName = "228) Azure Event Grid namespaces should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Namespaces deben deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/67dcad1a-ec60-45df-8fd0-14c9d29eeaa2" $Description $policyName $scope $displayName "Y" "Deny"
     
        # Azure Event Grid namespace topic broker should use private link
        # Effect Audit
        $policyName = "audit-privlink-egrdnamtopbro"
        $displayName = "229) Azure Event Grid namespace topic broker should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Namespace Topic Broker deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1301a000-bc6b-4d90-8414-7091e3abdc40" $Description $policyName $scope $displayName "Y" "Audit"
        
        # Azure Event Grid namespace MQTT broker should use private link
        # Effect Audit
        $policyName = "audit-privlink-egrdmqttbro"
        $displayName = "230) Azure Event Grid namespace MQTT broker should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Namespace MQTT Broker deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cd8f7644-6fe8-4516-bded-0e465ead03ac" $Description $policyName $scope $displayName "Y" "Audit"

        # Azure Machine Learning compute instances should be recreated to get the latest software updates 
        # Effect Audit
        $policyName = "audit-softupdates-mlw"
        $displayName = "231) Azure Machine Learning compute instances should be recreated to get the latest software updates"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben recrear las instancias computacionales obteniendo las últimas actualizaciones del software."
        ManageAzPolicy  "/providers/Microsoft.Authorization/policyDefinitions/f110a506-2dcb-422e-bcea-d533fc8c35e2" $Description $policyName $scope $displayName "Y"
        
        # Disk encryption should be enabled on Azure Data Explorer
        # Effect DENY
        $policyName = "deny-diskenc-dtex"
        $displayName = "232) Disk encryption should be enabled on Azure Data Explorer"
        $Description = "Para cumplir la linea base de seguridad de Azure, los Azure Data Explorer deben tener habilitado el cifrado a nivel de disco."
        ManageAzPolicy  "/providers/Microsoft.Authorization/policyDefinitions/f4b53539-8df9-40e4-86c6-6b607703bd4e" $Description $policyName $scope $displayName "Y" "Deny"
        
        # All Database Admin on Azure Data Explorer should be disabled
        # Effect DENY
        $policyName = "deny-dsibldadmin-dtex"
        $displayName = "233) All Database Admin on Azure Data Explorer should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure, los Azure Data Explorer deben deshabilitados todos los administradores de base de datos."
        ManageAzPolicy  "/providers/Microsoft.Authorization/policyDefinitions/8945ba5e-918e-4a57-8117-fe615d12e3ba" $Description $policyName $scope $displayName "Y" "Deny"
       
        # Azure Cache for Redis Enterprise should use private link
        # Effect AuditIfNotExists
        $policyName = "audit-plinkenterp-redis"
        $displayName = "234) Azure Cache for Redis Enterprise should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure las redis cache enterprise deben estar conectadas a una VNET"
        ManageAzPolicy  "/providers/Microsoft.Authorization/policyDefinitions/960e650e-9ce3-4316-9590-8ee2c016ca2f" $Description $policyName $scope $displayName "Y"
       
        # Azure Cache for Redis should not use access keys for authentication
        # Effect DENY
        $policyName = "deny-accesskeys-redis"
        $displayName = "235) Azure Cache for Redis should not use access keys for authentication"
        $Description = "Para cumplir la linea base de seguridad de Azure las redis cache deben tener deshabilitadas las llaves de acceso y en su lugar usar Microsoft Entra ID"
        ManageAzPolicy  "/providers/Microsoft.Authorization/policyDefinitions/3827af20-8f80-4b15-8300-6db0873ec901" $Description $policyName $scope $displayName "Y" "Deny"

        # Bot Protection should be enabled for Azure Application Gateway WAF 
        # Effect DENY
        $policyName = "deny-botprot-appgtwy"
        $displayName = "236) Bot Protection should be enabled for Azure Application Gateway WAF"
        $Description = "Para cumplir la linea base de seguridad de Azure los Application Gateway deben tener habilitada la proteccion contra bots."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ebea0d86-7fbd-42e3-8a46-27e7568c2525" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Azure Application Gateway should have Resource logs enabled
        # Effect AuditIfNotExists
        $policyName = "deny-reslog-appgtwy"
        $displayName = "237) Azure Application Gateway should have Resource logs enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Application Gateway deben enviar los logs hacia un Log Analytics."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8a04f872-51e9-4313-97fb-fc1c3543011c" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"
        
        # Azure Policy Add-on for Kubernetes service (AKS) should be installed and enabled on your clusters
        # Effect DENY
        $policyName = "deny-nakedpods-aks"
        $displayName = "238) Kubernetes cluster should not use naked pods"
        $Description = "Para cumplir la linea base de seguridad de Azure los clusters AKS no deben tener pods que no esten gestionados por el Kubernetes (naked pods)"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/65280eef-c8b4-425e-9aec-af55e55bf581" $Description $policyName $scope $displayName $null "Deny"

        # Role-Based Access Control (RBAC) should be used on Kubernetes Services
        # Effect Audit
        $policyName = "audit-rbac-aks"
        $displayName = "239) Role-Based Access Control (RBAC) should be used on Kubernetes Services"
        $Description = "Para cumplir la linea base de seguridad de Azure los AKS deben utilizar control de acceso bajo RBAC"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ac4a19c2-fa67-49b4-8ae5-0b2e78c49457" $Description $policyName $scope $displayName "Y" "Audit"

        # Kubernetes clusters should use internal load balancers
        # Effect DENY
        $policyName = "deny-intloadb-aks"
        $displayName = "240) Kubernetes clusters should use internal load balancers"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes deben usar balanceadores internos."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3fc4dc25-5baf-40d8-9b05-7fe74c1bc64e" $Description $policyName $scope $displayName $null "Deny"

        # Kubernetes clusters should use internal load balancers
        # Effect DENY
        $policyName = "deny-intloadb-aks"
        $displayName = "240) Kubernetes clusters should use internal load balancers"
        $Description = "Para cumplir la linea base de seguridad de Azure los cluster de Azure Kubernetes deben usar balanceadores internos."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3fc4dc25-5baf-40d8-9b05-7fe74c1bc64e" $Description $policyName $scope $displayName $null "Deny"

        # Container registries should not allow unrestricted network access
        # Effect DENY
        $policyName = "deny-restnetacc-acr"
        $displayName = "241) Container registries should not allow unrestricted network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben restringir el acceso a nivel de red."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3fc4dc25-5baf-40d8-9b05-7fe74c1bc64e" $Description $policyName $scope $displayName $null "Deny"

        # Container registries should be encrypted with a customer-managed key
        # Effect DENY
        $policyName = "deny-cmkey-acr"
        $displayName = "242) Container registries should be encrypted with a customer-managed key"
        $Description = "Para cumplir la linea base de seguridad de Azure los Azure Container Registry deben tener habilitado el cifrado en reposo con llaves administradas por XM"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5b9159ae-1701-4a6f-9a7a-aa9c8ddd0580" $Description $policyName $scope $displayName "Y" "Deny"

        # Machines should have secret findings resolved 
        # Effect AuditIfNotExists
        $policyName = "audit-secrets-vm"
        $displayName = "243) Machines should have secret findings resolved"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales no deben tener hallazgos relacionados a secretos, se debe usar Azure Key Vault"
        ManageAzPolicy  "/providers/Microsoft.Authorization/policyDefinitions/3ac7c827-eea2-4bde-acc7-9568cd320efa" $Description $policyName $scope $displayName "Y"

        # Only approved VM extensions should be installed
        # Effect AuditIfNotExists
        $policyName = "audit-apprvdext-vm"
        $guest="GuestAttestationExtension" # ["GuestAttestation","ChangeTracking-Windows","ChangeTracking-Linux","AADLoginForWindows","AzureBackupWindowsWorkload","SqlIaasExtension","MicrosoftMonitoringAgent"]
        $displayName = "244) Only approved VM extensions should be installed"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales solo deben utilizar extensiones previamente aprobadas"
        $extensions =@($guest)

        # Management ports should be closed on your virtual machines
        # Effect AuditIfNotExists
        $policyName = "audit-managports-vm"
        $displayName = "245) Management ports should be closed on your virtual machines"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales deben tener cerrados los puertos de administracion"
        ManageAzPolicy  "/providers/Microsoft.Authorization/policyDefinitions/22730e10-96f6-4aac-ad84-9383d35b5917" $Description $policyName $scope $displayName "Y"
        
        # Management ports of virtual machines should be protected with just-in-time network access control
        $policyName = "audit-jit-vm"
        $displayName = "246) Management ports of virtual machines should be protected with just-in-time network access control"
        $Description = "Para cumplir la linea base de seguridad de Azure las maquinas virtuales deben estar protegidos con JIT"
        ManageAzPolicy  "/providers/Microsoft.Authorization/policyDefinitions/b0f33259-77d7-4c9e-aac6-3aabcfae693c" $Description $policyName $scope $displayName "Y"
        
        # Storage accounts should restrict network access
        # Effect Deny
        $policyName = "deny-netaccess-storage"
        $displayName = "247) Storage accounts should restrict network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las storage accounts deben restringir el acceso a la red"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/34c877ad-507e-4c82-993e-3452a6e0ad3c" $Description $policyName $scope $displayName "Y" "Deny"
        
        # Storage accounts should use customer-managed key for encryption
        # Effect Audit
        $policyName = "audit-cmkey-storage"
        $displayName = "248) Storage accounts should use customer-managed key for encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure las storage accounts deben tener habilitado el cifrado en reposo con llaves administradas por el cliente"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6fac406b-40ca-413b-bf8e-0bf964659c25" $Description $policyName $scope $displayName "Y"
        
        # Function apps should enable end to end encryption 
        # Effect DENY
        $policyName = "deny-e2ecrypt-funcapp"
        $displayName = "249) Function apps should enable end to end encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las Azure Functions deben utilizar cifrado end to end"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/387140f1-6da9-4741-bcee-3b5edcdfd9ec" $Description $policyName $scope $displayName "Y" "Deny"

        # App Service apps should require FTPS
        # Effect AuditIfNotExists
        $policyName = "audit-ftps-webapp"
        $displayName = "250) [Evaluation] App Service apps should require FTPS only"
        $Description = "Para cumplir la linea base de seguridad de Azure ninguna Web App debe usar FTP en los despliegues."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4d24b6d4-5e53-4a4f-a7f4-618fa573ee4b" $Description $policyName $scope $displayName "Y"

        # App Service apps should only be accessible over HTTPS
        # Effect DENY
        $policyName = "deny-https-webapp"
        $displayName = "251) [Evaluation] App Service apps should only be accessible over HTTPS only"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las Web App deben tener habilitado el https only."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a4af4a39-4135-47fb-b175-47fbdf85311d" $Description $policyName $scope $displayName "Y" "Deny"
        
        # App Service apps should have remote debugging turned off
        # Effect AuditIfNotExists
        $policyName = "audit-debug-webapp"
        $displayName = "252) App Service apps should only be accessible over HTTPS only"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slot deben tener deshabilitado el debugging remoto."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cb510bfd-1cba-4d9f-a230-cb0976f4bb71" $Description $policyName $scope $displayName "Y"

        # App Service apps should use the latest TLS version 
        # Effect AuditIfNotExists
        $policyName = "audit-tls13-webapp"
        $displayName = "253) App Service apps should use the latest TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App no deben soportar versiones obsoletas de TLS"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b" $Description $policyName $scope $displayName "Y"
        
        # App Service apps should not have CORS configured to allow every resource to access your apps
        # Effect AuditIfNotExists
        $policyName = "audit-cors-webapp"
        $displayName = "254) App Service apps should not have CORS configured to allow every resource to access your apps"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App no deben permitir el acceso desde todos los dominios CORS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5744710e-cc2f-4ee8-8809-3b11e89f4bc9" $Description $policyName $scope $displayName "Y"

        # App Service apps should have authentication enabled
        # Effect AuditIfNotExists
        $policyName = "audit-auth-webapp"
        $displayName = "255) App Service apps should have authentication enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App deben requerir autenticacion."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/95bccee9-a7f8-4bec-9ee9-62c3473701fc" $Description $policyName $scope $displayName "Y"

        # App Service apps should use the latest TLS version
        # Effect AuditIfNotExists
        $policyName = "audit-tls13-webapp"
        $displayName = "256) App Service apps should use the latest TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App no deben soportar versiones obsoletas de TLS"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b" $Description $policyName $scope $displayName "Y"

        # App Service apps should not have CORS configured to allow every resource to access your apps
        # Effect AuditIfNotExists
        $policyName = "audit-cors-webapp"
        $displayName = "257) App Service apps should not have CORS configured to allow every resource to access your apps"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App no deben permitir el acceso desde todos los dominios CORS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5744710e-cc2f-4ee8-8809-3b11e89f4bc9" $Description $policyName $scope $displayName "Y"

        # App Service apps should have authentication enabled
        # Effect AuditIfNotExists
        $policyName = "audit-auth-webapp"
        $displayName = "258) App Service apps should have authentication enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App deben requerir autenticacion."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/95bccee9-a7f8-4bec-9ee9-62c3473701fc" $Description $policyName $scope $displayName "Y"

        # App Service apps should use latest HTTP Version
        # Effect AuditIfNotExists
        $policyName = "audit-httpv-webapp"
        $displayName = "259) App Service apps should use latest HTTP Version"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App deben utilizar unicamente la ultima version de HTTP."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8c122334-9d20-4eb8-89ea-ac9a705b74ae" $Description $policyName $scope $displayName "Y"

        # App Service apps should disable public network access
        # Effect DENY
        $policyName = "deny-publicaccess-webapp"
        $displayName = "260) App Service apps should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1b5ef780-c53c-4a64-87f3-bb9c8c8094ba" $Description $policyName $scope $displayName "Y" "Deny"

        # App Service apps should enable end to end encryption
        # Effect DENY
        $policyName = "deny-e2ecrypt-webapp"
        $displayName = "261) App Service apps should enable end to end encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure las Web App deben utilizar cifrado end to end."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/af1d7e88-c1c8-4ea8-be1f-87bff0df9101" $Description $policyName $scope $displayName "Y" "Deny"

        # Disks and OS image should support TrustedLaunch
        # Effect Audit
        $policyName = "audit-imgtrustedlau-vm"
        $displayName = "262) Disks and OS image should support TrustedLaunch"
        $Description = "Para cumplir la linea base de seguridad de Azure los las imagenes de disco y de sistema operativo deben soportar TrustedLaunch"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b03bb370-5249-4ea4-9fce-2552e87e45fa" $Description $policyName $scope $displayName "Y"

        # Function app slots should enable end to end encryption
        # Effect DENY
        $policyName = "deny-e2ecrypt-funcappslt"
        $displayName = "263) Function app slots should enable end to end encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure las function app slots deben utilizar cifrado end to end."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cbe0e5eb-fea9-491d-ab20-a62cf049c5ae" $Description $policyName $scope $displayName "Y" "Deny"

        # App Service app slots should require FTPS only
        # Effect AuditIfNotExists
        $policyName = "audit-ftps-webappslt"
        $displayName = "264) App Service app slots should require FTPS only"
        $Description = "Para cumplir la linea base de seguridad de Azure ningun web app slot debe usar FTP en los despliegues."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c285a320-8830-4665-9cc7-bbd05fc7c5c0" $Description $policyName $scope $displayName "Y"

        # App Service app slots should only be accessible over HTTPS
        # Effect Audit
        $policyName = "audit-https-webappslt"
        $displayName = "265) App Service app slots should only be accessible over HTTPS"
        $Description = "Para cumplir la linea base de seguridad de Azure los web app slot deben tener habilitado el https only."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ae1b9a8c-dfce-4605-bd91-69213b4a26fc" $Description $policyName $scope $displayName "Y"

        # App Service app slots should have remote debugging turned off
        # Effect AuditIfNotExists
        $policyName = "audit-debug-webappslt"
        $displayName = "266) App Service app slots should have remote debugging turned off"
        $Description = "Para cumplir la linea base de seguridad de Azure los web app slot deben tener deshabilitado el debugging remoto."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a08ae1ab-8d1d-422b-a123-df82b307ba61" $Description $policyName $scope $displayName "Y"

        # App Service app slots should use the latest TLS version
        # Effect AuditIfNotExists
        $policyName = "audit-tls13-webappslt"
        $displayName = "267) App Service app slots should use the latest TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure los web app slot no deben soportar versiones obsoletas de TLS"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4ee5b817-627a-435a-8932-116193268172" $Description $policyName $scope $displayName "Y"

        # App Service app slots should not have CORS configured to allow every resource to access your apps
        # Effect AuditIfNotExists
        $policyName = "audit-cors-webappslt"
        $displayName = "268) App Service app slots should not have CORS configured to allow every resource to access your apps"
        $Description = "Para cumplir la linea base de seguridad de Azure los web app slot no deben permitir el acceso desde todos los dominios CORS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cae7c12e-764b-4c87-841a-fdc6675d196f" $Description $policyName $scope $displayName "Y"

        # App Service app slots should use latest HTTP Version
        # Effect AuditIfNotExists
        $policyName = "audit-httpv-webappslt"
        $displayName = "269) App Service apps should use latest HTTP Version"
        $Description = "Para cumplir la linea base de seguridad de Azure los web app slot deben utilizar unicamente la ultima version de HTTP."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4dcfb8b5-05cd-4090-a931-2ec29057e1fc" $Description $policyName $scope $displayName "Y"
        
        # App Service app slots should disable public network access
        # Effect DENY
        $policyName = "deny-publicaccess-webappslt"
        $displayName = "270) App Service app slots should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los web app slot deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/701a595d-38fb-4a66-ae6d-fb3735217622" $Description $policyName $scope $displayName "Y" "Deny"

        # App Service app slots should enable end to end encryption
        # Effect DENY
        $policyName = "deny-e2ecrypt-webappslt"
        $displayName = "271) App Service app slots should enable end to end encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure los web app slot deben utilizar cifrado end to end."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/701a595d-38fb-4a66-ae6d-fb3735217622" $Description $policyName $scope $displayName "Y" "Deny"

        # App Service app slots should enable end to end encryption
        # Effect DENY
        $policyName = "deny-e2ecrypt-webappslt"
        $displayName = "272) App Service app slots should enable end to end encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure los web app slot deben utilizar cifrado end to end."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/123aed70-491a-4f07-a569-e1f3a8dd651e" $Description $policyName $scope $displayName "Y" "Deny"

        # Keys using RSA cryptography should have a specified minimum key size
        # Effect DENY
        $minlen=4096
        $policyName = "deny-keysize4096-kv"
        $displayName = "273) Keys using RSA cryptography should have a specified minimum key size"
        $Description = "Para cumplir la linea base de seguridad de Azure las llaves RSA deben tener un tamaño minimo de 4096 bytes"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/82067dbb-e53b-4e06-b631-546d197452d9" $Description $policyName $scope $displayName $null "Deny" $minlen "minimumRSAKeySize"
        
        # Keys should have the specified maximum validity period
        # Effect DENY
        $maxdays=365
        $policyName = "deny-keyexpiration-kv"
        $displayName = "274) Keys should have the specified maximum validity period"
        $Description = "Para cumplir la linea base de seguridad de Azure las llaves en keyvault deben tener una expiracion maxima de 365 dias"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/49a22571-d204-4c91-a7b6-09b1a586fbc9" $Description $policyName $scope $displayName $null "Deny" $maxdays "maximumValidityInDays"
        
        # Azure Key Vault should use RBAC permission model DENY
        $policyName = "deny-rbac-kv"
        $displayName = "275) Azure Key Vault should use RBAC permission model"
        $Description = "Para cumplir la linea base de seguridad de Azure los keyvault deben utilizar el esquema de permisos bajo Azure RBAC"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/12d4fa5e-1f9f-4c21-97a9-b99b3c6611b5" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure data factories should be encrypted with a customer-managed key
        # Effect DENY
        $policyName = "deny-cmkey-dtfy"
        $displayName = "276) Azure data factories should be encrypted with a customer-managed key"
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Factory deben tener habilitado el cifrado en reposo con llaves administradas por el cliente"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4ec52d6d-beb7-40c4-9a9e-fe753254690e" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Defender for SQL should be enabled for unprotected Azure SQL servers
        # Effect AuditIfNotExists
        $policyName = "audit-mdfcunptrctd-asql"
        $displayName = "277) Azure Defender for SQL should be enabled for unprotected Azure SQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure los servidores SQL destrotegidos deben tener habilitado el Microsoft Defender for SQL"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/abfb4388-5bf4-4ad7-ba82-2cd2f41ceae9" $Description $policyName $scope $displayName "Y"
        
        # SQL servers should use customer-managed keys to encrypt data at rest
        # Effect DENY
        $policyName = "deny-cmkey-asql"
        $displayName = "278) SQL servers should use customer-managed keys to encrypt data at rest"
        $Description = "Para cumplir la linea base de seguridad de Azure los servidores SQL deben tener habilitado el cifrado en reposo con llaves administradas por el cliente"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0a370ff3-6cab-4e85-8995-295fd854c5b8" $Description $policyName $scope $displayName "Y" "Deny"
        
        # SQL managed instances should use customer-managed keys to encrypt data at rest
        # Effect DENY
        $policyName = "deny-cmkey-asqlmi"
        $displayName = "279) SQL managed instances should use customer-managed keys to encrypt data at rest"
        $Description = "Para cumplir la linea base de seguridad de Azure los servidores SQL Managed deben tener habilitado el cifrado en reposo con llaves administradas por el cliente"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ac01ad65-10e5-46df-bdd9-6b0cad13e1d2" $Description $policyName $scope $displayName "Y" "Deny"

        # Service Bus Premium namespaces should use a customer-managed key for encryption
        # Effect Audit
        $policyName = "audit-cmkey-sbus"
        $displayName = "280) Service Bus Premium namespaces should use a customer-managed key for encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure los service bus premium deben tener habilitado el cifrado en reposo con llaves administradas por el cliente"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/295fc8b1-dc9f-4f53-9c61-3f313ceab40a" $Description $policyName $scope $displayName "Y"

        # Kubernetes cluster services should listen only on allowed ports 
        # Effect DENY
        $policyName = "deny-allwdports-aks"
        $ports=443
        $displayName = "281) Kubernetes cluster services should listen only on allowed ports"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios de Azure Kubernetes solo deben escuchar en puertos previamente aprobados"
        $arrports =@($ports)
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/233a2a17-77ca-4fb1-9b6b-69223d272a44" $Description $policyName $scope $displayName $null "Audit" $arrports "allowedServicePortsList"    

        # Automation Account should have Managed Identity
        # Effect Audit
        $policyName = "audit-mngid-aac"
        $displayName = "282) Automation Account should have Managed Identity"
        $Description = "Para cumplir la linea base de seguridad de Azure las Azure Automation Accounts deben usar managed identities"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/dea83a72-443c-4292-83d5-54a2f98749c0" $Description $policyName $scope $displayName "Y"
        
        # Automation accounts should disable public network access
        # Effect DENY
        $policyName = "deny-pubaccess-aac"
        $displayName = "283) Automation accounts should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las Azure Automation Accounts deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/955a914f-bf86-4f0e-acd5-e0766b0efcb6" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Automation accounts should use customer-managed keys to encrypt data at rest
        # Effect DENY
        $policyName = "deny-cmkey-aac"
        $displayName = "284) Azure Automation accounts should use customer-managed keys to encrypt data at rest"
        $Description = "Para cumplir la linea base de seguridad de Azure las Azure Automation Accounts deben tener habilitado el cifrado en reposo con llaves administradas por el cliente"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/56a5ee18-2ae6-4810-86f7-18e39ce5629b" $Description $policyName $scope $displayName "Y" "Deny"

        # Azure Automation account should have local authentication method disabled
        # Effect DENY
        $policyName = "deny-dlocalauth-aac"
        $displayName = "285) Azure Automation account should have local authentication method disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Azure Automation Accounts deben tener deshabilitada la autenticacion local y en su lugar se deben usar identidades de Microsoft Entra ID"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/48c5f1cb-14ad-4797-8e3b-f78ab3f8d700" $Description $policyName $scope $displayName "Y" "Deny"

        # Automation account variables should be encrypted
        # EFfect DENY
        $policyName = "deny-varenc-aac"
        $displayName = "286) Automation account variables should be encrypted"
        $Description = "Para cumplir la linea base de seguridad de Azure las Azure Automation Accounts deben cifrar sus variables para mantener la confidencialidad"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3657f5a0-770e-44a3-b44e-9431ba1e9735" $Description $policyName $scope $displayName "Y" "Deny"

        # Private endpoint connections on Automation Accounts should be enabled
        # Effect AuditIfNotExists
        $policyName = "audit-pendpoint-aac"
        $displayName = "273) Private endpoint connections on Automation Accounts should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Azure Automation Accounts deben estar conectadas a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0c2b3618-68a8-4034-a150-ff4abc873462" $Description $policyName $scope $displayName "Y" "AuditIfNotExists"
    }
}
Catch
{
    Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils"
    exit 
}
