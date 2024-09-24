# DeleteOldSnapshot-VM.ps1
# Runbook para la eliminación de snapshots discos de máquinas virtuales antiguas

$rg="<Resource Group Name>" # Nombre del grupo de recursos donde está la máquina relacionada a las snapshots.
$automationAccount = "<Azure Automation Account Name>" # Nombre de la automation account (Debe tener managed identity) donde se ejecuta el runbook.
$null = Disable-AzContextAutosave -Scope Process

try 
{
    $AzureConnection = (Connect-AzAccount -Identity).context
}
catch 
{
    Write-Output "No hay una managed identity asignada a la automation account "+$automationAccount 
    exit
}

$AzureContext = Set-AzContext -SubscriptionName $AzureConnection.Subscription -DefaultProfile $AzureConnection

$snaptodelete=Get-AzSnapshot -ResourceGroupName $rg | Where-Object {$_.TimeCreated -lt (Get-date).AddDays(-4) }

$snaptodelete | Remove-AzSnapshot -Force

if($snaptodelete)
{
    $snapName=$snaptodelete.Name
    Write-Output "La snapshot $snapName se elimino correctamente"
}
else
{
    Write-Output "No se elimino ninguna snapshot"
}