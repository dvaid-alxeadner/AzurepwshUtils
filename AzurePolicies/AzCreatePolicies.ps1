<#
.SYNOPSIS
This is a script for creating Azure Policies.

.DESCRIPTION
Deploy Azure Policies in a subscription for a given tenant_id and subscription_id

.PARAMETER 1
Subscription ID

.PARAMETER 2
Tenant ID

.PARAMETER 3
Scope

.EXAMPLE
PS> .\CreatePolicies.ps1 aaaaaaaa-bbbb-cccc-eeee-fffffffffff aaaaaaaa-bbbb-cccc-eeee-fffffffffff

.NOTES
@2021

.LINK
github.com/dvaid-alxeadner/AzurepwshUtils/tree/main/AzurePolicies

#>
param ($TenantId=$n,$SubscriptionId=$null,$scope=$null)

function ManageAzPolicy{ 
 
    Param ([string]$policyDefId,[string]$Description,[string]$policyName,[string]$scope,[string]$displayName,[string]$policySupportMessage=$null,[string]$effect=$null,$arrayParams=$null,[string]$nameParam)
    
    try
    {
        $definition = Get-AzPolicyDefinition | Where-Object { $_.PolicyDefinitionId -eq $policyDefId }    

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
                    $ResourceGroup = Get-AzResourceGroup -Name $scope
                    if ($ResourceGroup) 
                    {
                        $scope=$ResourceGroup.ResourceId
                    }
                    else 
                    {
                        Write-Host "Invalid scope $scope"
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
    else {
        Write-Host "Error:Subscription ID provided fails to comply the defined regular expression"
        exit 
    }
    
    if ($loginAZ)
    {
        # [Preview]: Storage account public access should be disallowed DENY
        # Effect Audit
        $policyName = "deny-publicaccess-strg"
        $displayName = "1) [Preview]: Storage account public access should be disallowed"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las cuentas de storage deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4fa4b6c0-31ca-4c0d-b10d-24b96f62a751" $Description $policyName $scope $displayName "Y"

        # Azure Defender for Storage should be enabled 
        # Effect AuditIFNotExists
        $policyName = "audit-azdf-strg"
        $displayName = "2) Azure Defender for Storage should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage deben tener habilitado el Azure Defender."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/308fbb08-4ab8-4e67-9b29-592e93fb94fa" $Description $policyName $scope $displayName "Y"

        # Secure transfer to storage accounts should be enabled DENY 
        # Effect Audit
        $policyName = "deny-sectransf-strg"
        $displayName = "3) Secure transfer to storage accounts should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las cuentas de almacenamiento deben tener habilitado el Secure Transfer."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9" $Description $policyName $scope $displayName "Y"

        # Storage accounts should allow access from trusted Microsoft services DENY
        # Effect Audit
        $policyName = "deny-mstrusted-strg"
        $displayName = "4) Storage accounts should allow access from trusted Microsoft services"
        $Description = "Para cumplir la linea base de seguridad de azure las cuentas de storage deben permitir el acceso desde los servicios de Microsoft confiables y que implementen autenticacion fuerte."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c9d007d0-c057-4772-b18c-01e546713bcd" $Description $policyName $scope $displayName "Y"
        
        # Storage accounts should prevent shared key access DENY
        # Effect Audit
        $policyName = "deny-SASdisable-strg"
        $displayName = "5) Storage accounts should prevent shared key access"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage deben tener deshabilitado el soporte de llaves de acceso, en su lugar se debe usar Azure AD."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8c6a50c6-9ffd-4ae7-986f-5fa6111f9a54" $Description $policyName $scope $displayName "Y"

        # Storage accounts should prevent cross tenant object replication DENY
        # Effect Audit
        $policyName = "deny-repcten-strg"
        $displayName = "6) Storage accounts should prevent cross tenant object replication"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage deben evitar la replicacion de objetos cross tenant."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/92a89a79-6c52-4a7e-a03f-61306fc49312" $Description $policyName $scope $displayName "Y"

        # Storage accounts should have infrastructure encryption DENY
        # Effect Audit
        $policyName = "deny-infraencrypt-strg"
        $displayName = "7) Storage accounts should have infrastructure encryption"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage deben tener cifrado a nivel de infraestructura."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4733ea7b-a883-42fe-8cac-97454c2a9e4a" $Description $policyName $scope $displayName "Y"

        # Require encryption on Data Lake Store accounts NO PARAMS
        $policyName = "deny-infraencrypt-dtlk"
        $displayName = "8) Require encryption on Data Lake Store accounts"
        $Description = "Para cumplir la linea base de seguridad de Azure los data lake deben tener cifrado a nivel de infraestructura."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a7ff3161-0087-490a-9ad9-ad6217f4f43a" $Description $policyName $scope $displayName "Y"

        # Storage accounts should have the specified minimum TLS version DENY
        # Effect Audit
        $policyName = "deny-tls12-strg"
        $displayName = "9) Storage accounts should have the specified minimum TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure las cuentas de storage no deben soportar versiones obsoletas de TLS."
        $minTLS = "TLS1_2"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fe83a0eb-a853-422d-aac2-1bffd182c5d0" $Description $policyName $scope $displayName "Y" "Audit" $minTLS "minimumTlsVersion"

        # Function apps should require FTPS only AuditIfNotExists
        $policyName = "audit-ftps-funcapp"
        $displayName = "10) FTPS only should be required in your Function App"
        $Description = "Para cumplir la linea base de seguridad de Azure ninguna Function App debe usar FTP en los despliegues."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/399b2637-a50f-4f95-96f8-3a145476eb15" $Description $policyName $scope $displayName "Y"

        # Function apps should only be accessible over HTTPS AuditIfNotExists
        $policyName = "audit-https-funcapp"
        $displayName = "11) Function apps should only be accessible over HTTPS"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las Function App deben tener habilitado el https only."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6d555dd1-86f2-4f1c-8ed7-5abae7c6cbab" $Description $policyName $scope $displayName "Y"

        # Function apps should have remote debugging turned off AuditIfNotExists
        $policyName = "audit-debug-funcapp"
        $displayName = "12) Function apps should have remote debugging turned off"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las Function App deben tener deshabilitado el debugging remoto."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0e60b895-3786-45da-8377-9c6b4b6ac5f9" $Description $policyName $scope $displayName "Y"
        
        # Latest TLS version should be used in your Function App AuditIfNotExists
        $policyName = "audit-tls-funcapp"
        $displayName = "13) Function apps should use the latest TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure las function app no deben soportar versiones obsoletas de TLS"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f9d614c5-c173-4d56-95a7-b4437057d193" $Description $policyName $scope $displayName "Y"

        # Function apps should not have CORS configured to allow every resource to access your apps AuditIfNotExists
        $policyName = "audit-cors-funcapp"
        $displayName = "14) CORS should not allow every resource to access your Function Apps"
        $Description = "Para cumplir la linea base de seguridad de Azure las function app no deben permitir el acceso desde todos los dominios CORS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0820b7b9-23aa-4725-a1ce-ae4558f718e5" $Description $policyName $scope $displayName "Y"

        # Function apps should have authentication enabled AuditIfNotExists
        $policyName = "audit-auth-funcapp"
        $displayName = "15) Function apps should have authentication enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las function app deben requerir autenticacion."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c75248c1-ea1d-4a9c-8fc9-29a6aabd5da8" $Description $policyName $scope $displayName "Y"

        # Function apps should use latest HTTP Version AuditIfNotExists
        $policyName = "audit-httpv-funcapp"
        $displayName = "16) Function apps should use latest HTTP Version"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las function deben utilizar unicamente la ultima version de HTTP."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e2c1c086-2d84-4019-bff3-c44ccd95113c" $Description $policyName $scope $displayName "Y"

        # Function apps should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-funcapp"
        $displayName = "17) Function apps should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las function app deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/969ac98b-88a8-449f-883c-2e9adb123127" $Description $policyName $scope $displayName "Y"

        # Function app slots should only be accessible over HTTPS DENY
        # Effect Audit
        $policyName = "deny-https-funcappslt"
        $displayName = "18) Function app slots should only be accessible over HTTPS"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slots deben tener ser accedidas solo por HTTPS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5e5dbe3f-2702-4ffc-8b1e-0cae008a5c71" $Description $policyName $scope $displayName "Y"

        # Function app slots should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-funcappslt"
        $displayName = "19) Function app slots should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slot deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/11c82d0c-db9f-4d7b-97c5-f3f9aa957da2" $Description $policyName $scope $displayName "Y"

        # Function app slots should have remote debugging turned off AuditIFNotExists
        $policyName = "audit-debug-funcappslt"
        $displayName = "20) Function app slots should have remote debugging turned off"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slot deben tener deshabilitado el debugging remoto."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/89691ef9-8c50-49a8-8950-9c7fba41699e" $Description $policyName $scope $displayName "Y"

        # Function app slots should not have CORS configured to allow every resource to access your apps AuditIfNotExists
        $policyName = "audit-cors-funcappslt"
        $displayName = "21) Function app slots should not have CORS configured to allow every resource to access your apps"
        $Description = "Para cumplir la linea base de seguridad de Azure los function app slot no deben permitir el acceso desde todos los dominios CORS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a1a22235-dd10-4062-bd55-7d62778f41b0" $Description $policyName $scope $displayName "Y"
  
        # Function app slots should use the latest TLS version AuditIFNotExists
        $policyName = "audit-tls12-funcappslt"
        $displayName = "22) Function app slots should use the latest TLS version"
        $Description = "Para cumplir la linea base de seguridad de Azure los function app slot no deben soportar versiones obsoletas de TLS"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/deb528de-8f89-4101-881c-595899253102" $Description $policyName $scope $displayName "Y"
        
        # Function app slots should require FTPS only AuditIFNotExists
        $policyName = "audit-ftps-funcappslt"
        $displayName = "23) Function app slots should require FTPS only"
        $Description = "Para cumplir la linea base de seguridad de Azure ningun function app slot debe usar FTP en los despliegues."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e1a09430-221d-4d4c-a337-1edb5a1fa9bb" $Description $policyName $scope $displayName "Y"

        # Function app slots should use latest HTTP Version AuditIFNotExists
        $policyName = "audit-httpv-funcappslt"
        $displayName = "24) Function app slots should only be accessible over HTTPS"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los function app slots deben utilizar unicamente la ultima version de HTTP."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fa98f1b1-1f56-4179-9faf-93ad82f3458f" $Description $policyName $scope $displayName "Y"

        # Key vaults should have soft delete enabled DENY
        # Effect Audit
        $policyName = "deny-softd-kv"
        $displayName = "25) Key vaults should have soft delete"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los key vault deben tener habilitado el soft delete"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d" $Description $policyName $scope $displayName "Y"

        # Key vaults should have purge protection enabled DENY
        # Effect Audit
        $policyName = "deny-purge-kv"
        $displayName = "26) Key vaults should have purge protection enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los key vault deben tener habilitado el purge protection"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0b60c0b2-2dc2-4e1c-b5c9-abbed971de53" $Description $policyName $scope $displayName "Y"

        # Azure Defender for Key Vault should be enabled AuditIfNotExists
        $policyName = "audit-azdf-kv"
        $displayName = "27) Azure Defender for Key Vault should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todos los key vault deben tener habilitado Azure Defender"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0e6763cc-5078-4e64-889d-ff4d9a839047" $Description $policyName $scope $displayName "Y"
        
        # Key Vault secrets should have an expiration date DENY
        # Effect Audit
        $policyName = "deny-expscr-kv"
        $displayName = "28) Key Vault secrets should have an expiration date"
        $Description = "Para cumplir la linea base de seguridad de Azure los secretos en los key vault deben tener configurada una fecha de expiracion."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/98728c90-32c7-4049-8429-847dc0f4fe37" $Description $policyName $scope $displayName $null

        # Key Vault keys should have an expiration date DENY
        # Effect Audit
        $policyName = "deny-expkey-kv"
        $displayName = "29) Key Vault keys should have an expiration date"
        $Description = "Para cumplir la linea base de seguridad de Azure las llaves en los Key Vault deben tener configurada una fecha de expiracion."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0" $Description $policyName $scope $displayName $null

        # Azure Key Vault should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-kv"
        $displayName = "30) Azure Key Vault should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de azure los key vault deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/405c5871-3e91-4644-8a63-58e19d68ff5b" $Description $policyName $scope $displayName "Y"

        # [Preview]: Private endpoint should be configured for Key Vault DENY
        # Effect Audit
        $policyName = "deny-pendpoint-kv"
        $displayName = "31) [Preview]: Private endpoint should be configured for Key Vault"
        $Description = "Para cumplir la linea base de seguridad de azure los key vault deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5f0bc445-3935-4915-9981-011aa2b46147" $Description $policyName $scope $displayName "Y"

        # [Preview]: Azure Data Factory linked services should use Key Vault for storing secrets DENY 
        # Effect Audit
        $policyName = "deny-kv-dtfy"
        $displayName = "32) [Preview]: Azure Data Factory linked services should use Key Vault for storing secrets"
        $Description = "Para cumplir la linea base de seguridad de Azure Data Factory debe utilizar Key Vault para almacenar secretos."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/127ef6d7-242f-43b3-9eef-947faf1725d0" $Description $policyName $scope $displayName "Y"

        # [Preview]: Azure Data Factory linked services should use system-assigned managed identity authentication when it is supported DENY 
        # Effect Audit
        $policyName = "deny-mngid-dtfy"
        $displayName = "33) [Preview]: Azure Data Factory linked services should use system-assigned managed identity authentication"
        $Description = "Para cumplir la linea base de seguridad de Azure Data Factory debe utilizar system managed identity para conectarse a recursos."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f78ccdb4-7bf4-4106-8647-270491d2978a" $Description $policyName $scope $displayName "Y"

        # SQL Server Integration Services integration runtimes on Azure Data Factory should be joined to a virtual network DENY
        # Effect Audit
        $policyName = "deny-ssisvnet-dtfy"
        $displayName = "34) SQL Server Integration Services integration runtimes on Azure Data Factory should be joined to a virtual network"
        $Description = "Para cumplir la linea base de seguridad de Azure los integration runtime SSIS en Data Factory deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0088bc63-6dee-4a9c-9d29-91cfdc848952" $Description $policyName $scope $displayName "Y"

        # Public network access on Azure Data Factory should be disabled DENY
        # Effect Audit
        $policyName = "deny-publicaccess-dtfy"
        $displayName = "35) Public network access on Azure Data Factory should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Factory deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1cf164be-6819-4a50-b8fa-4bcaa4f98fb6" $Description $policyName $scope $displayName "Y"
    
        # [Preview]: Azure Data Factory linked service resource type should be in allow list DENY
        # Effect Audit
        $policyName = "deny-lsallow-dtfy"
        $displayName = "36) [Preview]: Azure Data Factory linked service resource type should be in allow list"
        $Description = "Para cumplir la linea base de seguridad de Azure los Data Factory solo deben utilizar conectores previamente aprobados."
        $allowedLinkedServicesArray =@("AzureBlobStorage","AzureDatabricks","AzureDataLakeStore","AzureKeyVault","AzureSqlDatabase")
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6809a3d0-d354-42fb-b955-783d207c62a8" $Description $policyName $scope $displayName "Y" "Audit" $allowedLinkedServicesArray "allowedLinkedServiceResourceTypes"

        # [Preview]: Azure Data Factory should use a Git repository for source control AuditIfNotExists
        $policyName = "audit-git-dtfy"
        $displayName = "37) [Preview]: Azure Data Factory should use a Git repository for source control"
        $Description = "Para cumplir la linea base de seguridad de Azure Data Factory debe utilizar un repositorio Git para control de versiones."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/77d40665-3120-4348-b539-3192ec808307" $Description $policyName $scope $displayName "Y"

        # Azure SQL Database should be running TLS version 1.2 or newer DENY
        # Effect Audit
        $policyName = "deny-tls12-asql"
        $displayName = "38) Azure SQL Database should be running TLS version 1.2 or newer"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las bases de datos Azure SQL deben usar la ultima version disponible de TLS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/32e6bbec-16b6-44c2-be37-c5b672d103cf" $Description $policyName $scope $displayName "Y"

        # Azure Defender for Azure SQL Database servers should be enabled AuditIfNotExists
        $policyName = "audit-azdf-asql"
        $displayName = "39) Azure Defender for Azure SQL Database servers should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener habilitado el Azure Defender."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/7fe3b40f-802b-4cdd-8bd4-fd799c948cc2" $Description $policyName $scope $displayName "Y"

        # An Azure Active Directory administrator should be provisioned for SQL servers AuditIfNotExists
        $policyName = "audit-aadadmin-asql"
        $displayName = "40) An Azure Active Directory administrator should be provisioned for SQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener configurado un administrador de Azure Active Directory"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1f314764-cb73-4fc9-b863-8eca98ac36e9" $Description $policyName $scope $displayName "Y"

        # SQL Managed Instance should have the minimal TLS version of 1.2 Audit
        $policyName = "audit-tls-asqlmi"
        $displayName = "41) SQL Managed Instance should have the minimal TLS version of 1.2"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las bases de datos Azure SQL Managed deben usar la ultima version disponible de TLS."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a8793640-60f7-487c-b5c3-1d37215905c4" $Description $policyName $scope $displayName "Y"

        # Transparent Data Encryption on SQL databases should be enabled AuditIfNotExists
        $policyName = "audit-tde-asql"
        $displayName = "42) Transparent Data Encryption on SQL databases should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las bases de datos Azure SQL deben tener habilitado TDE (Transparent Data Encryption)."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/17k78e20-9358-41c9-923c-fb736d382a12" $Description $policyName $scope $displayName "Y"

        # Azure SQL Database should have Azure Active Directory Only Authentication DENY
        # Effect Audit
        $policyName = "deny-aadauth-asql"
        $displayName = "43) Azure SQL Database should have Azure Active Directory Only Authentication"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben implementar Autenticacion de Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/abda6d70-9778-44e7-84a8-06713e6db027" $Description $policyName $scope $displayName "Y"

        # Azure SQL Managed Instance should have Azure Active Directory Only Authentication DENY
        # Effect Audit
        $policyName = "deny-aadauth-asqlmi"
        $displayName = "44) Azure SQL Managed Instance should have Azure Active Directory Only Authentication"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL Managed deben implementar Autenticacion de Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/78215662-041e-49ed-a9dd-5385911b3a1f" $Description $policyName $scope $displayName "Y"

        # Public network access on Azure SQL Database should be disabled DENY
        # Effect Audit
        $policyName = "deny-publicaccess-asql"
        $displayName = "45) Public network access on Azure SQL Database should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1b8ca024-1d5c-4dec-8995-b1a932b41780" $Description $policyName $scope $displayName "Y"

        # Azure SQL Managed Instances should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-asqlmi"
        $displayName = "46) Azure SQL Managed Instances should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL Managed deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/9dfea752-dd46-4766-aed1-c355fa93fb91" $Description $policyName $scope $displayName "Y"

        # Azure Defender for SQL servers on machines should be enabled AuditIFNotExists
        $policyName = "audit-azdfmach-asql"
        $displayName = "47) Azure Defender for SQL servers on machines should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos SQL Server en maquinas deben tener habilitado el Azure Defender."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6581d072-105e-4418-827f-bd446d56421b" $Description $policyName $scope $displayName "Y"

        # Azure Defender for SQL should be enabled for unprotected SQL Managed Instances AuditIFNotExists
        $policyName = "audit-azdf-asqlunprotected"
        $displayName = "48) Azure Defender for SQL should be enabled for unprotected SQL Managed Instances"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL sin proteger deben tener habilitado el Azure Defender."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/abfb7388-5bf4-4ad7-ba99-2cd2f41cebb9" $Description $policyName $scope $displayName "Y"

        # Auditing on SQL server should be enabled AuditIFNotExists
        $policyName = "audit-audit-asql"
        $displayName = "49) Auditing on SQL server should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL debe tener habilitada la auditoria a nivel de servidor."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9" $Description $policyName $scope $displayName "Y"

        # SQL Auditing settings should have Action-Groups configured to capture critical activities AuditIFNotExists
        $policyName = "audit-auditcritical-asql"
        $displayName = "50) SQL Auditing settings should have Action-Groups configured to capture critical activities"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben capturar eventos criticos en sus logs de auditoria."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/7ff426e2-515f-405a-91c8-4f2333442eb5" $Description $policyName $scope $displayName "Y"

        # Vulnerability assessment should be enabled on SQL Managed Instance AuditIFNotExists
        $policyName = "audit-vulnass-asqlmi"
        $displayName = "51) Vulnerability assessment should be enabled on SQL Managed Instance"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL Managed deben tener habilitado el analisis de vulnerabilidades."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1b7aa243-30e4-4c9e-bca8-d0d3022b634a" $Description $policyName $scope $displayName "Y"

        # Vulnerability assessment should be enabled on your SQL servers AuditIFNotExists
        $policyName = "audit-vulnass-asql"
        $displayName = "52) Vulnerability assessment should be enabled on your SQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener habilitado el analisis de vulnerabilidades."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ef2a8f2a-b3d9-49cd-a8a8-9a3aaaf647d9" $Description $policyName $scope $displayName "Y"

        # Vulnerability Assessment settings for SQL server should contain an email address to receive scan reports AuditIFNotExists
        $policyName = "audit-vulnmail-asql"
        $displayName = "53) Vulnerability Assessment settings for SQL server should contain an email address to receive scan reports"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener configurada una direccion de correo para el envio de los analisis de vulnerabilidades."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/057d6cfe-9c4f-4a6d-bc60-14420ea1f1a9" $Description $policyName $scope $displayName "Y"

        # SQL servers on machines should have vulnerability findings resolved AuditIFNotExists
        $policyName = "audit-vulnresolvedmach-asql"
        $displayName = "54) SQL servers on machines should have vulnerability findings resolved"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL en maquinas deben tener solucionadas las vulnerabilidades reportadas por el Defender For Azure SQL Databases."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6ba6d016-e7c3-4842-b8f2-4992ebc0d72d" $Description $policyName $scope $displayName "Y"

        # SQL databases should have vulnerability findings resolved AuditIFNotExists
        $policyName = "audit-vulnresolved-asql"
        $displayName = "55) SQL databases should have vulnerability findings resolved"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener solucionadas las vulnerabilidades reportadas por el Defender For Azure SQL Databases."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/feedbf84-6b99-488c-acc2-71c829aa5ffc" $Description $policyName $scope $displayName "Y"

        # SQL servers with auditing to storage account destination should be configured with 90 days retention or higher AuditIfNotExists
        $policyName = "audit-90retentionaudit-asql"
        $displayName = "56) SQL servers with auditing to storage account destination should be configured with 90 days retention or higher"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos Azure SQL deben tener mas de 90 dias de retencion en los logs de auditoria."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/89099bee-89e0-4b26-a5f4-165451757743" $Description $policyName $scope $displayName "Y"

        # All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace DENY
        # Effect Audit
        $policyName = "deny-authrules-sbus"
        $displayName = "57) All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las reglas de autorizacion excepto RootManageSharedAccessKey deben ser removidas del namespace del service bus."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a1817ec0-a368-432a-8057-8371e17ac6ee" $Description $policyName $scope $displayName "Y"

        # Service Bus namespaces should have double encryption enabled DENY
        # Effect Audit
        $policyName = "deny-doubleencrypt-sbus"
        $displayName = "58) Service Bus namespaces should have double encryption enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los namespace del service bus deben tener habilitado el doble cifrado."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ebaf4f25-a4e8-415f-86a8-42d9155bef0b" $Description $policyName $scope $displayName "Y"

        # Azure Service Bus namespaces should have local authentication methods disabled DENY
        # Effect Audit
        $policyName = "deny-dlocalauth-sbus"
        $displayName = "59) Azure Service Bus namespaces should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Service Bus deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cfb11c26-f069-4c14-8e36-56c394dae5af" $Description $policyName $scope $displayName "Y"

        # Resource logs in Service Bus should be enabled AuditIfNotExist
        $policyName = "audit-reslogs-sbus"
        $displayName = "60) Resource logs in Service Bus should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Service bus deben retener los logs del recurso por un periodo de tiempo superior a 90 dias."
        $requireRetentionDays = "90"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f8d36e2f-389b-4ee4-898d-21aeb69a0f45" $Description $policyName $scope $displayName "Y" "AuditIfNotExists" $requireRetentionDays "requiredRetentionDays"

        # Service Bus Namespaces should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-sbus"
        $displayName = "61) Service Bus Namespaces should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Service bus deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/cbd11fd3-3002-4907-b6c8-579f0e700e13" $Description $policyName $scope $displayName "Y"

        # Azure Service Bus namespaces should use private link AuditIFNotExists
        $policyName = "audit-plink-sbus"
        $displayName = "62) Azure Service Bus namespaces should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Service bus deben estar conectados a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1c06e275-d63d-4540-b761-71f364c2111d" $Description $policyName $scope $displayName "Y"

        # Cognitive Services accounts should use a managed identity DENY
        # Effect Audit
        $policyName = "deny-mid-cgntserv"
        $displayName = "63) Cognitive Services accounts should use a managed identity"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben usar una managed identity."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fe3fd216-4f83-4fc1-8984-2bbec80a3418" $Description $policyName $scope $displayName "Y"

        # Cognitive Services accounts should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-cgntserv"
        $displayName = "64) Cognitive Services accounts should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0725b4dd-7e76-479c-a735-68e7ee23d5ca" $Description $policyName $scope $displayName "Y"

        # Azure Cognitive Search services should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-cgntservsrch"
        $displayName = "65) Azure Cognitive Search services should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos de busqueda deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ee980b6d-0eca-4501-8d54-f6290fd512c3" $Description $policyName $scope $displayName "Y"

        # Azure Cognitive Search services should have local authentication methods disabled DENY AuditIFNotExists
        $policyName = "deny-dlocalauth-cgntservsrch"
        $displayName = "66) Azure Cognitive Search services should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos de busqueda deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6300012e-e9a4-4649-b41f-a85f5c43be91" $Description $policyName $scope $displayName "Y"

        # Cognitive Services accounts should have local authentication methods disabled DENY
        # Effect Audit
        $policyName = "deny-dlocalauth-cgntserv"
        $displayName = "67) Cognitive Services accounts should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/71ef260a-8f18-47b7-abcb-62d0673d94dc" $Description $policyName $scope $displayName "Y"

        # Azure Cognitive Search service should use a SKU that supports private link DENY
        # Effect Audit
        $policyName = "deny-skuplink-cgntserv"
        $displayName = "68) Azure Cognitive Search service should use a SKU that supports private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben usar SKUs que soporten Private Link."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/a049bf77-880b-470f-ba6d-9f21c530cf83" $Description $policyName $scope $displayName "Y"

        # Cognitive Services accounts should restrict network access DENY
        # Effect Audit
        $policyName = "deny-restricnetaccess-cgntserv"
        $displayName = "69) Cognitive Services accounts should restrict network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios cognitivos deben restringir el acceso a nivel de red."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/037eea7a-bd0a-46c5-9a66-03aea78705d3" $Description $policyName $scope $displayName "Y"

        # Log Analytics Workspaces should block non-Azure Active Directory based ingestion AuditIFNotExists DENY
        # Effect Audit
        $policyName = "deny-nonaad-loganaw"
        $displayName = "70) Log Analytics Workspaces should block non-Azure Active Directory based ingestion"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios de log analytics deben bloquear las ingestas que no esten basadas en Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e15effd4-2278-4c65-a0da-4d6f6d1890e2" $Description $policyName $scope $displayName "Y"
 
        # Log Analytics workspaces should block log ingestion and querying from public networks AuditIFNotExists DENY
        # Effect Audit
        $policyName = "deny-public-loganaw"
        $displayName = "71) Log Analytics workspaces should block log ingestion and querying from public networks"
        $Description = "Para cumplir la linea base de seguridad de Azure los servicios de log analytics deben bloquear las ingestas y consultas desde redes publicas."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6c53d030-cc64-46f0-906d-2bc061cd1334" $Description $policyName $scope $displayName "Y"

        # Azure Cosmos DB key based metadata write access should be disabled NO PARAMS
        $policyName = "audit-wrtkeyaccess-cosmos"
        $displayName = "72) Azure Cosmos DB key based metadata write access should be disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben deshabilitar el acceso de escritura basado en llaves."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4750c32b-89c0-46af-bfcb-2e4541a818d5" $Description $policyName $scope $displayName "Y"

        # Microsoft Defender for Azure Cosmos DB should be enabled AuditIFNotExists
        $policyName = "audit-azdf-cosmos"
        $displayName = "73) Microsoft Defender for Azure Cosmos DB should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben tener habilitado Azure Defender"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/adbe85b5-83e6-4350-ab58-bf3a4f736e5e" $Description $policyName $scope $displayName "Y"

        # Cosmos DB database accounts should have local authentication methods disabled DENY
        # Effect Audit
        $policyName = "deny-dlocalauth-cosmos"
        $displayName = "74) Cosmos DB database accounts should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5450f5bd-9c72-4390-a9c4-a7aba4edfdd2" $Description $policyName $scope $displayName "Y"
        
        # Azure Cosmos DB should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-cosmos"
        $displayName = "75) Azure Cosmos DB should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben tener deshabilitado el acceso publico."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/797b37f7-06b8-444c-b1ad-fc62867f335a" $Description $policyName $scope $displayName "Y"

        # CosmosDB accounts should use private link Audit
        $policyName = "audit-plink-cosmos"
        $displayName = "76) CosmosDB accounts should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure las Cosmos DB deben estar conectadaas a una VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/58440f8a-10c5-4151-bdce-dfbaad4a20b7" $Description $policyName $scope $displayName "Y"

        # API Management subscriptions should not be scoped at the All API scope. DENY
        # Effect Audit
        $policyName = "deny-allapiscope-apimgm"
        $displayName = "77) API Management subscriptions should not be scoped at the All API scope"
        $Description = "Para cumplir la linea base de seguridad de Azure las suscripciones del API Management no deben usar el scope All API"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3aa03346-d8c5-4994-a5bc-7652c2a2aef1" $Description $policyName $scope $displayName "Y"

        # API Management minimum API version should be set to 2019-12-01 or higher DENY
        # Effect Audit
        $policyName = "deny-api20191201-apimgm"
        $displayName = "78) API Management minimum API version should be set to 2019-12-01 or higher"
        $Description = "Para cumplir la linea base de seguridad de Azure la version minima de API debe ser 2019-12-01"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/549814b6-3212-4203-bdc8-1548d342fb67" $Description $policyName $scope $displayName "Y"

        # API Management service should use a SKU that supports virtual networks DENY
        # Effect Audit
        $policyName = "deny-skuvnet-apimgm"
        $displayName = "79) API Management service should use a SKU that supports virtual networks"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management deben usar SKUs que soporten VNET."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/73ef9241-5d81-4cd4-b483-8443d1730fe5" $Description $policyName $scope $displayName "Y"

        # API Management calls to API backends should not bypass certificate thumbprint or name validation DENY
        # Effect Audit
        $policyName = "deny-bypasscrt-apimgm"
        $displayName = "80) API Management calls to API backends should not bypass certificate thumbprint or name validation"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management no deben saltar la validacion de nombres y de firmas de certificados."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/92bb331d-ac71-416a-8c91-02f2cb734ce4" $Description $policyName $scope $displayName "Y"

        # API Management direct API Management endpoint should not be enabled DENY
        # Effect Audit
        $policyName = "deny-directendp-apimgm"
        $displayName = "81) API Management direct API Management endpoint should not be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management no deben tener habilitado el endpoint directo."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/b741306c-968e-4b67-b916-5675e5c709f4" $Description $policyName $scope $displayName "Y"

        # API Management calls to API backends should be authenticated DENY
        # Effect Audit
        $policyName = "deny-authbackend-apimgm"
        $displayName = "82) API Management calls to API backends should be authenticated"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management deben autenticarse ante los backend."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c15dcc82-b93c-4dcb-9332-fbf121685b54" $Description $policyName $scope $displayName "Y"

        # API Management APIs should use encrypted protocols only DENY
        # Effect Audit
        $policyName = "deny-encproto-apimgm"
        $displayName = "83) API Management APIs should use encrypted protocols only"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management solo deben usar protocolos con cifrado."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ee7495e7-3ba7-40b6-bfee-c29e22cc75d4" $Description $policyName $scope $displayName "Y"

        # API Management Named Values secrets should be stored in Azure KeyVault DENY
        # Effect Audit
        $policyName = "deny-kevynamval-apimgm"
        $displayName = "84) API Management Named Values secrets should be stored in Azure KeyVault"
        $Description = "Para cumplir la linea base de seguridad de Azure los API Management named values deben estar almacenados en un Key Vault."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f1cc7827-022c-473e-836e-5a51cae0b249" $Description $policyName $scope $displayName "Y"

        # Public network access should be disabled for MySQL servers DENY AuditIFNotExists
        $policyName = "deny-publicaccess-mysql"
        $displayName = "85) Public network access should be disabled for MySQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL deben tener desahabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/d9844e8a-1437-4aeb-a32c-0c992f056095" $Description $policyName $scope $displayName "Y"

        # Infrastructure encryption should be enabled for Azure Database for MySQL servers DENY AuditIfNotExist (No hay parametros)
        $policyName = "deny-infraenc-mysql"
        $displayName = "86) Infrastructure encryption should be enabled for Azure Database for MySQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL deben tener cifrado a nivel de infraestructura"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/3a58212a-c829-4f13-9872-6371df2fd0b4" $Description $policyName $scope $displayName "Y"

        # Private endpoint should be enabled for MySQL servers AuditIFNotExists
        $policyName = "audit-pendpoint-mysql"
        $displayName = "87) Private endpoint should be enabled for MySQL servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL deben estar conectadas a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/7595c971-233d-4bcf-bd18-596129188c49" $Description $policyName $scope $displayName "Y"

        # Public network access should be disabled for MySQL flexible servers DENY
        # Effect Audit
        $policyName = "deny-publicaccess-mysqlflex"
        $displayName = "88) Public network access should be disabled for MySQL flexible servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL flexibles deben tener desahabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/c9299215-ae47-4f50-9c54-8a392f68a052" $Description $policyName $scope $displayName "Y"

        # Enforce SSL connection should be enabled for MySQL database servers Audit
        $policyName = "audit-ssl-mysql"
        $displayName = "89) Enforce SSL connection should be enabled for MySQL database servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MySQL deben utilizar cifrado en transporte"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e802a67a-daf5-4436-9ea6-f6d821dd0c5d" $Description $policyName $scope $displayName "Y"

        # Public network access should be disabled for MariaDB servers DENY
        # Effect Audit
        $policyName = "deny-publicaccess-mariadb"
        $displayName = "90) Public network access should be disabled for MariaDB servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MariaDB deben tener desahabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/fdccbe47-f3e3-4213-ad5d-ea459b2fa077" $Description $policyName $scope $displayName "Y"

        # Private endpoint should be enabled for MariaDB servers AuditIFNotExists
        $policyName = "audit-pendpoint-mariadb"
        $displayName = "91) Private endpoint should be enabled for MariaDB servers"
        $Description = "Para cumplir la linea base de seguridad de Azure las bases de datos MariaDB deben estar conectadas a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/0a1302fb-a631-4106-9753-f3d494733990" $Description $policyName $scope $displayName "Y" 

        # Bot Service should have public network access disabled DENY
        # Effect Audit
        $policyName = "deny-publicaccess-bots"
        $displayName = "92) Bot Service should have public network access disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Bot Service deben tener desahabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/5e8168db-69e3-4beb-9822-57cb59202a9d" $Description $policyName $scope $displayName "Y"

        # Bot Service endpoint should be a valid HTTPS URI DENY
        # Effect Audit
        $policyName = "deny-validURI-bots"
        $displayName = "93) Bot Service endpoint should be a valid HTTPS URI"
        $Description = "Para cumplir la linea base de seguridad de azure los Azure Bot Service deben utilizar https"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/6164527b-e1ee-4882-8673-572f425f5e0a" $Description $policyName $scope $displayName "Y"

        # Bot Service resources should use private link Audit
        $policyName = "audit-plink-bots"
        $displayName = "94) BotService resources should use private link"
        $Description = "Para cumplir la linea base de seguridad de azure los Azure Bot Service deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ad5621d6-a877-4407-aa93-a950b428315e" $Description $policyName $scope $displayName "Y" 
        
        # Bot Service should have local authentication methods disabled DENY
        # Effect Audit
        $policyName = "deny-dlocalauth-bots"
        $displayName = "95) Bot Service should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de azure los Azure Bot Service deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ffea632e-4e3a-4424-bf78-10e179bb2e1a" $Description $policyName $scope $displayName "Y"

        # Machine Learning computes should have local authentication methods disabled DENY
        # Effect Audit
        $policyName = "deny-dlocalauth-mlw"
        $displayName = "96) Machine Learning computes should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e96a9a5f-07ca-471b-9bc5-6a0f33cbd68f" $Description $policyName $scope $displayName "Y"

        # Azure Machine Learning workspaces should disable public network access DENY
        # Effect Audit
        $policyName = "deny-publicaccess-mlw"
        $displayName = "97) Azure Machine Learning workspaces should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/438c38d2-3772-465a-a9cc-7a6666a275ce" $Description $policyName $scope $displayName "Y"
        
        # Azure Machine Learning workspaces should use private link DENY
        # Effect Audit
        $policyName = "deny-plink-mlw"
        $displayName = "98) Azure Machine Learning workspaces should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/40cec1dd-a100-4920-b15b-3024fe8901ab" $Description $policyName $scope $displayName "Y"

        # Resource logs in Azure Machine Learning workspace should be enabled AuditIFNotExists
        $policyName = "audit-reslogs-mlw"
        $displayName = "99) Resource logs in Azure Machine Learning workspace should be enabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Machine Learning deben retener los logs del recurso por un periodo de tiempo superior a 90 dias."
        $requireRetentionDays = "90"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/afe0c3be-ba3b-4544-ba52-0c99672a8ad6" $Description $policyName $scope $displayName "Y" "AuditIfNotExists" $requireRetentionDays "requiredRetentionDays"

        # Azure Event Grid topics should disable public network access DENY
        # Effect Audit
        $policyName = "audit-publicaccess-egridtop"
        $displayName = "100) Azure Event Grid topics should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Topics deben deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/1adadefe-5f21-44f7-b931-a59b54ccdb45" $Description $policyName $scope $displayName "Y"
     
        # Azure Event Grid topics should use private link Audit
        $policyName = "audit-plink-egridtop"
        $displayName = "101) Azure Event Grid topics should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/4b90e17e-8448-49db-875e-bd83fb6f804f" $Description $policyName $scope $displayName "Y"

        # Azure Event Grid topics should have local authentication methods disabled DENY
        # Effect Audit
        $policyName = "deny-dlocalauth-egridtop"
        $displayName = "102) Azure Event Grid topics should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Topics deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/ae9fb87f-8a17-4428-94a4-8135d431055c" $Description $policyName $scope $displayName "Y"

        # Azure Event Grid domains should have local authentication methods disabled DENY
        # Effect Audit
        $policyName = "deny-dlocalauth-egriddom"
        $displayName = "103) Azure Event Grid domains should have local authentication methods disabled"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Domains deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8bfadddb-ee1c-4639-8911-a38cb8e0b3bd" $Description $policyName $scope $displayName "Y"

        # Azure Event Grid domains should use private link Audit
        $policyName = "audit-plink-egriddom"
        $displayName = "104) Azure Event Grid domains should use private link"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Domains deben estar conectados a una VNET"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/9830b652-8523-49cc-b1b3-e17dce1127ca" $Description $policyName $scope $displayName "Y"

        # Azure Event Grid domains should disable public network access DENY
        # Effect Audit
        $policyName = "audit-publicaccess-egriddom"
        $displayName = "105) Azure Event Grid domains should disable public network access"
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid Domains deben deben tener deshabilitado el acceso publico"
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/f8f774be-6aee-492a-9e29-486ef81f3a68" $Description $policyName $scope $displayName "Y"
    
        # Azure Event Grid partner namespaces should have local authentication methods disabled DENY
        # Effect Audit
        $policyName = "deny-dlocalauth-egridpartnamsp"
        $displayName = "106) Azure Event Grid partner namespaces should have local authentication methods disabled "
        $Description = "Para cumplir la linea base de seguridad de Azure los Event Grid partner namespaces deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/8632b003-3545-4b29-85e6-b2b96773df1e" $Description $policyName $scope $displayName "Y"
     
        # Subnets should be associated with a Network Security Group AuditIfNotExist
        $policyName = "audit-sbnet-nsg"
        $displayName = "107) Subnets should be associated with a Network Security Group"
        $Description = "Para cumplir la linea base de seguridad de Azure todas las subredes deben estar asociadas a un Network Security Group con reglas especificas."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/e71308d3-144b-4262-b144-efdc3cc90517" $Description $policyName $scope $displayName "Y"

        # Flow logs should be enabled for every network security group Audit                                                                     
        $policyName = "audit-flowlogs-nsg"
        $displayName = "108) Flow logs should be enabled for every network security group"
        $Description = "Para cumplir la linea base de seguridad de Azure los Network Security Group deben tener habilitador los logs."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/27960feb-a23c-4577-8d36-ef8b5f35e0be" $Description $policyName $scope $displayName "Y"

        # Gateway subnets should not be configured with a network security group NO PARAMETER
        $policyName = "audit-gwsbnet-nsg"
        $displayName = "109) Gateway subnets should not be configured with a network security group"
        $Description = "Para cumplir la linea base de seguridad de las Gateway subnets no deben tener un Network Security Group."
        ManageAzPolicy "/providers/Microsoft.Authorization/policyDefinitions/35f9c03a-cc27-418e-9c0c-539ff999d010" $Description $policyName $scope $displayName "Y"
    }
}
Catch
{
    Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils"
    exit 
}
