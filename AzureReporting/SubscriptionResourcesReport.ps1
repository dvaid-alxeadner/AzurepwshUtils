<#
.SYNOPSIS
This is a script for extracting resources from a Subscription in Azure

.DESCRIPTION
Generate a list of resources in an Azure Subscription for analysis in Excel, requires ImportExcel Module: "Install-Module ImportExcel -AllowClobber -Scope CurrentUser"

.PARAMETER 1
Subscription ID

.PARAMETER 2
Tenant ID

.EXAMPLE
PS> .\SubscriptionResourcesReport.ps1 $SubscriptionId $Tenant

.NOTES
@2022

.LINK
github.com/dvaid-alxeadner/AzurepwshUtils/tree/main/AzurepwshUtils

#>
param ($beta='N',$scope=$null)

#Avanzada
#$SubscriptionId="dfd0e0a4-4e92-4005-97e1-2f8aca3ed4e8"
#Produccion
#$SubscriptionId="5f404e7e-02e9-408a-9550-df27c93d33b8"
#Hub
$SubscriptionId="e9ba7be7-6071-4cba-8cd0-dd3f10fdefa4"

$TenantId="c980e410-0b5c-48bc-bd1a-8b91cabc84bc"

$loginAZ=Connect-AzAccount -Tenant $TenantId -SubscriptionId $SubscriptionId

$rg=Get-AzResourceGroup
$outData = [System.Collections.Generic.List[Object]]::new()

if ($loginAZ) 
{
    foreach ($rows in $rg)
    {

        $resource=Get-AzResource -ResourceGroupName $rows.ResourceGroupName

        foreach ($resources in $resource)
        {
            $resourceGroup=$rows.ResourceGroupName
            $resourceGroupLocation=$rows.Location

            $kind=$resources.Kind
            $resourceLocation=$resources.Location
            $resourceName=$resources.ResourceName
            $resourceType=$resources.Type
            $resourceSubscription=$resources.SubscriptionId
            $resourceCreationTime=$resource.CreatedTime
            $resourceChangedTime=$resource.ChangedTime

            $CustomData=[PSCustomObject][Ordered]@{
                resourceGroupName=$resourceGroup
                resourceGroupLocation=$resourceGroupLocation
                resourceName=$resourceName
                resourceLocation=$resourceLocation
                resourceType=$resourceType
                resourceKind=$kind
                resourceSubscription=$resourceSubscription
            }
            $OutData.Add($CustomData)

            #$customDataJson=$customData|ConvertTo-Json
        }
    }
    $OutData | Sort-Object {$_.resourceGroupName -as [string]} | Select-Object resourceGroupName, resourceGroupLocation, resourceName, resourceLocation, resourceType, resourceKind, resourceSubscription | Out-GridView
    $OutData | Export-Excel
    Write-Host $outData
}
else {
    Write-Host "Login Failed"
}
