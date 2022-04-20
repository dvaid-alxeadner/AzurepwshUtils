$environment=$args[0]

#. Policies.ps1

$SubscriptionId = 'aaaaaaaa-bbbb-cccc-eeee-fffffffffff'

$TenantPosto = 'aaaaaaaa-bbbb-cccc-eeee-fffffffffff'

try {
    
    # Connect To Azure (Interactive Login)
    Connect-AzAccount -Tenant $TenantPosto -SubscriptionId $SubscriptionId
    
    # Authentication should be enabled on your API app
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Authentication should be enabled on your API app" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las API App deben requerir autenticacion."
    $pol = New-AzPolicyAssignment -Name "audit-api-auth" -DisplayName "1) Authentication should be enabled on your API app" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Authentication should be enabled on your Function app
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Authentication should be enabled on your Function app" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las Function App deben requerir autenticacion."
    $pol = New-AzPolicyAssignment -Name "audit-function-auth" -DisplayName "2) Authentication should be enabled on your Function app" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Authentication should be enabled on your web app
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Authentication should be enabled on your web app" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las Web App deben requerir autenticacion."
    $pol = New-AzPolicyAssignment -Name "audit-web-auth" -DisplayName "3) Authentication should be enabled on your web app" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # [Preview]: Storage account public access should be disallowed DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "[Preview]: Storage account public access should be disallowed" }    
    $Description = "Para cumplir el estandar de azure todas las cuentas de storage deben tener deshabilitado el acceso publico."
    $pol = New-AzPolicyAssignment -Name "audit-publicaccess-storage" -DisplayName "4) [Preview]: Storage account public access should be disallowed" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Defender for Storage should be enabled
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Defender for Storage should be enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure las cuentas de storage deben tener habilitado el Azure Defender."
    $pol = New-AzPolicyAssignment -Name "audit-azdf-strg" -DisplayName "5) Azure Defender for Storage should be enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
        
    # Secure transfer to storage accounts should be enabled DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Secure transfer to storage accounts should be enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las cuentas de almacenamiento deben tener habilitado el flag de Secure Transfer."
    $pol = New-AzPolicyAssignment -Name "audit-sectransfer-storage" -DisplayName "6) Secure transfer to storage accounts should be enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Storage accounts should allow access from trusted Microsoft services DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Storage accounts should allow access from trusted Microsoft services" }
    $Description = "Para cumplir el estandar de seguridad de azure las cuentas de storage deben permitir el acceso desde los servicios de Microsoft confiables."
    $pol = New-AzPolicyAssignment -Name "audit-trusted-storage" -DisplayName "7) Storage accounts should allow access from trusted Microsoft services" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Subnets should be associated with a Network Security Group
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Subnets should be associated with a Network Security Group" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las subredes deben estar asociadas a un Network Security Group administrado por Seguridad TI."
    $pol = New-AzPolicyAssignment -Name "audit-nsg-subnet" -DisplayName "8) Subnets should be associated with a Network Security Group" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # All network ports should be restricted on network security groups associated to your virtual machine
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "All network ports should be restricted on network security groups associated to your virtual machine" }
    $Description = "Para cumplir el estandar de seguridad de Azure deben existir restricciones de puertos en los Network Security Groups."
    $pol = New-AzPolicyAssignment -Name "audit-nsgports-vm" -DisplayName "9) All network ports should be restricted on network security groups associated to your virtual machine" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # [Preview]: Azure Data Factory linked services should use Key Vault for storing secrets DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "[Preview]: Azure Data Factory linked services should use Key Vault for storing secrets" }
    $Description = "Para cumplir el estandar de seguridad de Azure Data Factory debe utilizar Key Vault para almacenar secretos."
    $pol = New-AzPolicyAssignment -Name "audit-kvsec-dtfy" -DisplayName "10) [Preview]: Azure Data Factory linked services should use Key Vault for storing secrets" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # [Preview]: Azure Data Factory linked services should use system-assigned managed identity authentication when it is supported
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "[Preview]: Azure Data Factory linked services should use system-assigned managed identity authentication when it is supported" }
    $Description = "Para cumplir el estandar de seguridad de Azure Data Factory debe utilizar una managed identity para los tipos de autenticacion que lo soporten."
    $pol = New-AzPolicyAssignment -Name "audit-mngid-dtfy" -DisplayName "11) [Preview]: Azure Data Factory linked services should use systemassigned managed identity authentication when it is supported" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # [Preview]: Azure Data Factory should use a Git repository for source control DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "[Preview]: Azure Data Factory should use a Git repository for source control" }
    $Description = "Para cumplir el estandar de seguridad de Azure Data Factory debe utilizar un repositorio Git para control de versiones."
    $pol = New-AzPolicyAssignment -Name "audit-git-dtfy" -DisplayName "12) [Preview]: Azure Data Factory should use a Git repository for source control" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Internet-facing virtual machines should be protected with network security groups
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Internet-facing virtual machines should be protected with network security groups" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las maquinas virtuales deben tener Network Security Groups administrados por Seguridad TI asociados ya sea a la tarjeta de red, a la subred que se conectan o ambos."
    $pol = New-AzPolicyAssignment -Name "audit-ynet-vm" -DisplayName "13) Internet-facing virtual machines should be protected with network security groups" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Non-internet-facing virtual machines should be protected with network security groups
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Non-internet-facing virtual machines should be protected with network security groups" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las maquinas virtuales deben tener Network Security Groups administrados por Seguridad TI asociados ya sea a la tarjeta de red, a la subred que se conectan o ambos."
    $pol = New-AzPolicyAssignment -Name "audit-nnet-vm" -DisplayName "14) Non-internet-facing virtual machines should be protected with network security groups" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # FTPS only should be required in your Function App
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "FTPS only should be required in your Function App" }
    $Description = "Para cumplir el estandar de azure todas las Function App deben usar FTPS en los despliegues."
    $pol = New-AzPolicyAssignment -Name "audit-ftps-funcapp" -DisplayName "15) FTPS only should be required in your Function App" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
    
    # FTPS should be required in your Web App
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "FTPS should be required in your Web App" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las Web App deben usar FTPS en los despliegues."
    $pol = New-AzPolicyAssignment -Name "audit-ftps-webapp" -DisplayName "16) FTPS should be required in your Web App" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # FTPS only should be required in your API App
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "FTPS only should be required in your API App" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las API App deben usar FTPS en los despliegues."
    $pol = New-AzPolicyAssignment -Name "audit-ftps-apiapp" -DisplayName "17) FTPS only should be required in your API App" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Function App should only be accessible over HTTPS
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Function App should only be accessible over HTTPS" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las Function App deben tener habilitado el flag de https only."
    $pol = New-AzPolicyAssignment -Name "audit-https-funcapp" -DisplayName "18) Function App should only be accessible over HTTPS" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Web Application should only be accessible over HTTPS
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Web Application should only be accessible over HTTPS" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las WebApp deben tener habilitado el flag de https only."
    $pol = New-AzPolicyAssignment -Name "audit-https-webapp" -DisplayName "19) Web Application should only be accessible over HTTPS" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # API App should only be accessible over HTTPS
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "API App should only be accessible over HTTPS" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las API App deben tener habilitado el flag de https only."
    $pol = New-AzPolicyAssignment -Name "audit-https-apiapp" -DisplayName "20) API App should only be accessible over HTTPS" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure SQL Database should have the minimal TLS version of 1.2
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure SQL Database should have the minimal TLS version of 1.2" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las bases de datos Azure SQL deben usar la ultima version disponible de TLS."
    $pol = New-AzPolicyAssignment -Name "audit-tls-asqls" -DisplayName "21) Azure SQL Database should have the minimal TLS version of 1.2" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Defender for Azure SQL Database servers should be enabled
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Defender for Azure SQL Database servers should be enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure las bases de datos SQL Server deben tener habilitado el Azure Defender."
    $pol = New-AzPolicyAssignment -Name "audit-azdf-asqls" -DisplayName "22) Azure Defender for Azure SQL Database servers should be enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # An Azure Active Directory administrator should be provisioned for SQL servers
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "An Azure Active Directory administrator should be provisioned for SQL servers" }
    $Description = "Para cumplir el estándar de seguridad de Azure todas las bases de datos SQL Server deben tener asignado un administrador de Azure Active Directory."
    $pol = New-AzPolicyAssignment -Name "audit-bd-aadadmin" -DisplayName "23) An Azure Active Directory administrator should be provisioned for SQL servers" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # SQL Managed Instance should have the minimal TLS version of 1.2
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "SQL Managed Instance should have the minimal TLS version of 1.2" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las bases de datos Azure SQL deben usar la ultima version disponible de TLS."
    $pol = New-AzPolicyAssignment -Name "audit-tls-asqlsmi" -DisplayName "24) SQL Managed Instance should have the minimal TLS version of 1.2" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Transparent Data Encryption on SQL databases should be enabled
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Transparent Data Encryption on SQL databases should be enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las bases de datos SQL deben tener habilitado TDE (Transparent Data Encryption)."
    $pol = New-AzPolicyAssignment -Name "audit-bd-tde" -DisplayName "25) Transparent Data Encryption on SQL databases should be enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Cosmos DB accounts should have firewall rules DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Cosmos DB accounts should have firewall rules" }
    $Description = "Para cumplir el estandar de seguridad de Azure las bases de datos Cosmos deben tener configurado un firewall administrado por seguridad TI."
    $pol = New-AzPolicyAssignment -Name "audit-cosmos-firewall" -DisplayName "26) Azure Cosmos DB accounts should have firewall rules" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Cognitive Services accounts should use a managed identity DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Cognitive Services accounts should use a managed identity" }
    $Description = "Para cumplir el estandar de seguridad de Azure los componentes de cognitive services deben utilizar una managed identity."
    $pol = New-AzPolicyAssignment -Name "audit-mngid-cs" -DisplayName "27) Cognitive Services accounts should use a managed identity" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Machine Learning workspaces should use user-assigned managed identity DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Machine Learning workspaces should use user-assigned managed identity" }
    $Description = "Para cumplir el estandar de seguridad de Azure los workspaces de Machine Learning deben utilizar una managed identity."
    $pol = New-AzPolicyAssignment -Name "audit-mngid-mlw" -DisplayName "28) Azure Machine Learning workspaces should use user-assigned managed identity" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
    
    # Azure Machine Learning workspaces should use private link DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Machine Learning workspaces should use private link" }
    $Description = "Para cumplir el estandar de seguridad de Azure los workspaces de Machine Learning deben estar conectados a una VNET."
    $pol = New-AzPolicyAssignment -Name "audit-plink-mlw" -DisplayName "29) Azure Machine Learning workspaces should use private link" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
    
    # Latest TLS version should be used in your Web App
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Latest TLS version should be used in your Web App" }
    $Description = "Para cumplir el estándar de seguridad de Azure las function app no deben soportar ni TLS 1.0 ni TLS 1.1"
    $pol = New-AzPolicyAssignment -Name "audit-tls12-webapp" -DisplayName "30) Latest TLS version should be used in your Web App" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Latest TLS version should be used in your Function App
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Latest TLS version should be used in your Function App" }
    $Description = "Para cumplir el estándar de seguridad de Azure las function app no deben soportar ni TLS 1.0 ni TLS 1.1"
    $pol = New-AzPolicyAssignment -Name "audit-tls12-func" -DisplayName "31) Latest TLS version should be used in your Function App" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Latest TLS version should be used in your API App
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Latest TLS version should be used in your API App" }
    $Description = "Para cumplir el estandar de seguridad de Azure las API app no deben soportar ni TLS 1.0 ni TLS 1.1."
    $pol = New-AzPolicyAssignment -Name "audit-tls12-apiapp" -DisplayName "32) Latest TLS version should be used in your API App" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
 
    # Remote debugging should be turned off for Function Apps
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Remote debugging should be turned off for Function Apps" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las Function App deben tener deshabilitado el debugging remoto."
    $pol = New-AzPolicyAssignment -Name "audit-debug-funcapp" -DisplayName "33) Remote debugging should be turned off for Function Apps" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Remote debugging should be turned off for API Apps
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Remote debugging should be turned off for API Apps" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las API App deben tener deshabilitado el debugging remoto."
    $pol = New-AzPolicyAssignment -Name "audit-debug-apiapp" -DisplayName "34) Remote debugging should be turned off for API Apps" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Remote debugging should be turned off for Web Applications
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Remote debugging should be turned off for Web Applications" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las Web App deben tener deshabilitado el debugging remoto."
    $pol = New-AzPolicyAssignment -Name "audit-debug-webapp" -DisplayName "35) Remote debugging should be turned off for Web Applications" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # CORS should not allow every resource to access your Web Applications
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "CORS should not allow every resource to access your Web Applications" }
    $Description = "Para cumplir el estandar de seguridad de Azure las web app no deben permitir el acceso desde todos los dominios en las configuraciones CORS."
    $pol = New-AzPolicyAssignment -Name "audit-cors-webapp" -DisplayName "36) CORS should not allow every resource to access your Web Applications" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
   
    # CORS should not allow every resource to access your Function Apps
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "CORS should not allow every resource to access your Function Apps" }
    $Description = "Para cumplir el estandar de seguridad de Azure las function app no deben permitir el acceso desde todos los dominios en las configuraciones CORS."
    $pol = New-AzPolicyAssignment -Name "audit-cors-funcapp" -DisplayName "37) CORS should not allow every resource to access your Function Apps" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # CORS should not allow every resource to access your API App
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "CORS should not allow every resource to access your API App" }
    $Description = "Para cumplir el estandar de seguridad de Azure las API app no deben permitir el acceso desde todos los dominios en las configuraciones CORS."
    $pol = New-AzPolicyAssignment -Name "audit-cors-apiapp" -DisplayName "38) CORS should not allow every resource to access your API App" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Cache for Redis should reside within a virtual network DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Cache for Redis should reside within a virtual network" }
    $Description = "Para cumplir el estandar de seguridad de azure las redis cache deben estar conectadas a una VNET."
    $pol = New-AzPolicyAssignment -Name "audit-vnet-redis" -DisplayName "39) Azure Cache for Redis should reside within a virtual network" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Only secure connections to your Azure Cache for Redis should be enabled DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Only secure connections to your Azure Cache for Redis should be enabled" }
    $Description = "Para cumplir el estandar de seguridad de azure las redis cache solo deben aceptar conexiones seguras."
    $pol = New-AzPolicyAssignment -Name "audit-https-redis" -DisplayName "40) Only secure connections to your Azure Cache for Redis should be enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Event Grid topics should use private link
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Event Grid topics should use private link" }
    $Description = "Para cumplir el estándar de seguridad de Azure los Event Grid deben estar conectados a una VNET."
    $pol = New-AzPolicyAssignment -Name "audit-egridt-plink" -DisplayName "41) Azure Event Grid topics should use private link" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Event Grid domains should use private link
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Event Grid domains should use private link" }
    $Description = "Para cumplir el estándar de Seguridad de Event Grid deben estar conectado a una VNET."
    $pol = New-AzPolicyAssignment -Name "audit-egridd-plink" -DisplayName "42) Azure Event Grid domains should use private link" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure DDoS Protection Standard should be enabled
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure DDoS Protection Standard should be enabled" }
    $Description = "Para cumplir el estándar de Seguridad de Azure, las VNET deben tener habilitado DDoS protection standard."
    $pol = New-AzPolicyAssignment -Name "audit-ddos-enabled" -DisplayName "43) Azure DDoS Protection Standard should be enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Enforce SSL connection should be enabled for MySQL database servers
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Enforce SSL connection should be enabled for MySQL database servers" }
    $Description = "Para cumplir el estándar de seguridad de azure las bases de datos MySQL deben tener habilitado el SSL para cifrado en transporte."
    $pol = New-AzPolicyAssignment -Name "audit-ssl-mysql" -DisplayName "44) Enforce SSL connection should be enabled for MySQL database servers" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Key vaults should have soft delete enabled DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Key vaults should have soft delete enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las key vault deben tener habilitada la configuracion de Soft Delete"
    $pol = New-AzPolicyAssignment -Name "audit-kv-softd" -DisplayName "45) Key vaults should have soft delete enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
 
    # Key vaults should have purge protection enabled DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Key vaults should have purge protection enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las key vault deben tener habilitada la configuracion de Purge protection"
    $pol = New-AzPolicyAssignment -Name "audit-kv-purge" -DisplayName "46) Key vaults should have purge protection enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # [Preview]: Firewall should be enabled on Key Vault DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "[Preview]: Firewall should be enabled on Key Vault" }
    $Description = "Para cumplir el estandar de seguridad de Azure las Key Vault deben tener un firewall administrado por seguridad TI."
    $pol = New-AzPolicyAssignment -Name "audit-kv-fw" -DisplayName "47) [Preview]: Firewall should be enabled on Key Vault" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Defender for Key Vault should be enabled
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Defender for Key Vault should be enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las key vault deben tener habilitado Azure Defender"
    $pol = New-AzPolicyAssignment -Name "audit-azdf-kv" -DisplayName "48) Azure Defender for Key Vault should be enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
    
    # Pendiente revisar por que no la encuentra
    # [Preview]: Key Vault secrets should have an expiration date DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "[Preview]: Key Vault secrets should have an expiration date" }
    $Description = "Para cumplir el estandar de seguridad de Azure los secretos en los Key Vault deben tener configurada una fecha de expiracion."
    $pol = New-AzPolicyAssignment -Name "audit-kvscr-expiration" -DisplayName "49) [Preview]: Key Vault secrets should have an expiration date" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Pendiente revisar por que no la encuentra
    # [Preview]: Key Vault keys should have an expiration date DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "[Preview]: Key Vault keys should have an expiration date" }
    $Description = "Para cumplir el estandar de seguridad de Azure las llaves en los Key Vault deben tener configurada una fecha de expiracion."
    $pol = New-AzPolicyAssignment -Name "audit-kvkey-expiration" -DisplayName "50) [Preview]: Key Vault keys should have an expiration date" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Web Application Firewall (WAF) should be enabled for Application Gateway DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Web Application Firewall (WAF) should be enabled for Application Gateway" }
    $Description = "Para cumplir el estandar de seguridad de Azure los Application Gateway deben tener habilitadas las funciones de WAF."
    $pol = New-AzPolicyAssignment -Name "audit-appgtwy-waf" -DisplayName "51) Web Application Firewall (WAF) should be enabled for Application Gateway" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Web Application Firewall (WAF) should use the specified mode for Application Gateway DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Web Application Firewall (WAF) should use the specified mode for Application Gateway" }
    $Description = "Para cumplir el estandar de seguridad de Azure los Application Gateway deben utilizar en el WAF bajo el modo prevencion"
    $pol = New-AzPolicyAssignment -Name "audit-appgtwy-prev" -DisplayName "52) Web Application Firewall (WAF) should use the specified mode for Application Gateway" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"


    
    # All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace" }
    $Description = "Para cumplir el estandar de seguridad de Azure todas las reglas de autorizacion excepto RootManageSharedAccessKey deben ser removidas del namespace del service bus"
    $pol = New-AzPolicyAssignment -Name "audit-sbus-rootmanage" -DisplayName "53) All authorization rules except RootManageSharedAccessKey should be removed from Service Bus namespace" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Service Bus namespaces should have double encryption enabled DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Service Bus namespaces should have double encryption enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure los namespace del service bus deben tener habilitado el doble cifrado"
    $pol = New-AzPolicyAssignment -Name "audit-sbus-doubleenc" -DisplayName "54) Service Bus namespaces should have double encryption enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # 2021-10-29
    # Configure Cosmos DB database accounts to disable local authentication enable MODIFY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Configure Cosmos DB database accounts to disable local authentication" }
    $Description = "Para cumplir el estandar de seguridad de Azure las Cosmos DB deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
    $pol = New-AzPolicyAssignment -Name "audit-cosmos-dlocalauth" -DisplayName "55) Configure Cosmos DB database accounts to disable local authentication" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Cosmos DB key based metadata write access should be disabled enable
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Cosmos DB key based metadata write access should be disabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure las Cosmos DB deben tener deshabilitado el acceso de escritura basado en metadatos y llave."
    $pol = New-AzPolicyAssignment -Name "audit-cosmos-kbmwaccesa" -DisplayName "56) Azure Cosmos DB key based metadata write access should be disabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Storage accounts should prevent shared key access enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Storage accounts should prevent shared key access" }
    $Description = "Para cumplir el estandar de seguridad de Azure las cuentas de storage deben tener deshabilitado el soporte de Shared Key Access."
    $pol = New-AzPolicyAssignment -Name "audit-SASdisable-storage" -DisplayName "57) Storage accounts should prevent shared key access" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Kubernetes Service Clusters should have local authentication methods enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Kubernetes Service Clusters should have local authentication methods disabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure los cluster de Azure Kubernetes deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
    $pol = New-AzPolicyAssignment -Name "audit-aks-dlocalauth" -DisplayName "58) Azure Kubernetes Service Clusters should have local authentication methods disabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes cluster containers should only use allowed images enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes cluster containers should only use allowed images" }
    $Description = "Para cumplir el estandar de seguridad de Azure los cluster de Azure Kubernetes solo deben permitir el uso de imagenes seguras."
    $pol = New-AzPolicyAssignment -Name "audit-aks-allowimg" -DisplayName "59) Kubernetes cluster containers should only use allowed images" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes cluster containers should only use allowed ProcMountType enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes cluster containers should only use allowed ProcMountType" }
    $Description = "Para cumplir el estandar de seguridad de Azure los cluster de Azure Kubernetes solo deben permitir ProcMountType en los contenedores. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-procmountty" -DisplayName "60) Kubernetes cluster containers should only use allowed ProcMountType" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes cluster containers should run with a read only root file system enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes cluster containers should run with a read only root file system" }
    $Description = "Para cumplir el estandar de seguridad de Azure los cluster de Azure Kubernetes deben ejecutarse con un filesystem root de solo lectura. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-readoroot" -DisplayName "61) Kubernetes cluster containers should run with a read only root file system" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes clusters should not grant CAP_SYS_ADMIN security capabilities enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes clusters should not grant CAP_SYS_ADMIN security capabilities" }
    $Description = "Para cumplir el estandar de seguridad de Azure los cluster de Azure Kubernetes no deben ejecutarse bajo el contexto de seguridad CAP_SYS_ADMIN. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-cpapsyadmin" -DisplayName "62) Kubernetes clusters should not grant CAP_SYS_ADMIN security capabilities" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes cluster containers should only use allowed capabilities enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes cluster containers should only use allowed capabilities" }
    $Description = "Para cumplir el estandar de seguridad de Azure y los numerales 5.2.8 y 5.2.9 de CIS los cluster de Azure Kubernetes deben usar solamente capacidades permitidas. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-allowcapab" -DisplayName "63) Kubernetes cluster containers should only use allowed capabilities" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes clusters should not use the default namespace enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes clusters should not use the default namespace" }
    $Description = "Para cumplir el estandar de seguridad de Azure los cluster de Azure Kubernetes no deben usar el namespace por omision. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-defname" -DisplayName "64) Kubernetes clusters should not use the default namespace" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes cluster should not allow privileged containers enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes cluster should not allow privileged containers" }
    $Description = "Para cumplir el estandar de seguridad de Azure y el numeral 5.2.1 de CIS los cluster de Azure Kubernetes no deben usar contenedores privilegiados. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-noprivcontainers" -DisplayName "65) Kubernetes cluster should not allow privileged containers" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes cluster pods should only use approved host network and port range enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes cluster pods should only use approved host network and port range" }
    $Description = "Para cumplir el estandar de seguridad de Azure y el numeral 5.2.4 de CIS los pods de los cluster de Azure Kubernetes solo deben usar redes y puertos aprobados. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-approvednetport" -DisplayName "66) Kubernetes cluster pods should only use approved host network and port range" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"
    
    # Kubernetes cluster containers should not share host process ID or host IPC namespace enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes cluster containers should not share host process ID or host IPC namespace" }
    $Description = "Para cumplir el estandar de seguridad de Azure y los numerales 5.2.2. y 5.2.3 de CIS los pods de los cluster de Azure Kubernetes no deben exponer los proceess ID de host o el namespace IPC del host. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-hostIDIPC" -DisplayName "67) Kubernetes cluster containers should not share host process ID or host IPC namespace" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes clusters should not allow container privilege escalation enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes clusters should not allow container privilege escalation" }
    $Description = "Para cumplir el estandar de seguridad de Azure y el numeral 5.2.5 de CIS los cluster de Azure Kubernetes no deben permitir el escalamiento de privilegios. For more information, see https://aka.ms/kubepolicydoc."
    $pol = New-AzPolicyAssignment -Name "audit-aks-noroot" -DisplayName "68) Kubernetes clusters should not allow container privilege escalation" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes clusters should be accessible only over HTTPS enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes clusters should be accessible only over HTTPS" }
    $Description = "Para cumplir el estandar de seguridad de Azure los cluster de Azure Kubernetes solo se pueden acceder sobre HTTPS."
    $pol = New-AzPolicyAssignment -Name "audit-aks-https" -DisplayName "69) Kubernetes clusters should be accessible only over HTTPS" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Service Bus namespaces should have local authentication methods disabled enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Service Bus namespaces should have local authentication methods disabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure los Service Bus deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
    $pol = New-AzPolicyAssignment -Name "audit-sbus-dlocalauth" -DisplayName "70) Azure Service Bus namespaces should have local authentication methods disabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Kubernetes Service Private Clusters should be enabled enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Kubernetes Service Private Clusters should be enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure los cluster de Azure Kubernetes deben ser privados."
    $pol = New-AzPolicyAssignment -Name "audit-aks-privclu" -DisplayName "71) Azure Kubernetes Service Private Clusters should be enabled" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Kubernetes Services should be upgraded to a non-vulnerable Kubernetes version enable AUDIT
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Kubernetes Services should be upgraded to a non-vulnerable Kubernetes version" }
    $Description = "Para cumplir el estandar de seguridad de Azure los servicios de Azure Kubernetes deben actualizarse a versiones no vulnerables."
    $pol = New-AzPolicyAssignment -Name "audit-aks-novuln" -DisplayName "72) Kubernetes Services should be upgraded to a non-vulnerable Kubernetes version" -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Configure container registries to disable local authentication enable MODIFY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Configure container registries to disable local authentication" }
    $Description = "Para cumplir el estandar de seguridad de Azure los Azure Container Registry deben tener deshabilitada la autenticacion local y en su lugar se debe realizar mediante Azure Active Directory."
    $pol = New-AzPolicyAssignment -Name "audit-acr-dlocalauth" -DisplayName "73) Configure container registries to disable local authentication." -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Vulnerabilities in Azure Container Registry images should be remediated enable AUDIT
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Vulnerabilities in Azure Container Registry images should be remediated" }
    $Description = "Para cumplir el estandar de seguridad de Azure los servicios Azure Container Registry deben tener remediadas las vulnerabilidades"
    $pol = New-AzPolicyAssignment -Name "audit-acr-novuln" -DisplayName "74) Vulnerabilities in Azure Container Registry images should be remediated." -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Public network access should be disabled for Container registries enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Public network access should be disabled for Container registries" }
    $Description = "Para cumplir el estandar de seguridad de Azure los servicios Azure Container Registry deben tener deshabilitado el acceso público sobre la red"
    $pol = New-AzPolicyAssignment -Name "audit-acr-nopubnet" -DisplayName "75) Public network access should be disabled for Container registries." -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Container registries should have exports disabled enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Container registries should have exports disabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure los servicios Azure Container Registry deben tener deshabilitados los export"
    $pol = New-AzPolicyAssignment -Name "audit-acr-noexport" -DisplayName "76) Container registries should have exports disabled." -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Container registries should have SKUs that support Private Links enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Container registries should have SKUs that support Private Links" }
    $Description = "Para cumplir el estandar de seguridad de Azure los servicios Azure Container Registry deben usar SKUs que soporten Private Link"
    $pol = New-AzPolicyAssignment -Name "audit-acr-plink" -DisplayName "77) Container registries should have SKUs that support Private Links." -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Azure Defender for container registries should be enabled enable AUDIT
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Azure Defender for container registries should be enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure los servicios Azure Container Registry deben tener habilitado Azure Defender"
    $pol = New-AzPolicyAssignment -Name "audit-acr-azdef" -DisplayName "78) Azure Defender for container registries should be enabled." -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Container registries should not allow unrestricted network access enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Container registries should not allow unrestricted network access" }
    $Description = "Para cumplir el estandar de seguridad de Azure los servicios Azure Container Registry no deben permitir el acceso a la red sin restricciones"
    $pol = New-AzPolicyAssignment -Name "audit-acr-nounrenet" -DisplayName "79) Container registries should not allow unrestricted network access." -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

    # Configure Azure Defender for Kubernetes to be enabled enable DENY
    $definition = Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq "Configure Azure Defender for Kubernetes to be enabled" }
    $Description = "Para cumplir el estandar de seguridad de Azure los servicios de Azure Kubernetes deben tener habilitado Azure Defender."
    $pol = New-AzPolicyAssignment -Name "audit-aks-azdef" -DisplayName "80) Configure Azure Defender for Kubernetes to be enabled." -Description $Description -PolicyDefinition $definition -Scope "/subscriptions/$($SubscriptionId)"
    Write-Host $pol+"`n"

}
Catch
{
    Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils" 
    exit 
}
