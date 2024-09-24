# TakeSnapshot-VM.ps1
# Runbook para la creación de snapshots de discos de máquinas virtuales

$rg="<Resource Group Name>" # Nombre del grupo de recursos donde está la máquina a la que se le desea generar el la snapshot.
$automationAccount = "<Azure Automation Account Name>" # Nombre de la automation account (Debe tener managed identity) donde se ejecuta el runbook.
$location="<Azure Location>" # Nombre la región donde se generará la snapshot.
$vmName="<Virtual Machine Name>" # Nombre de la máquina a la que se le generará la snapshot.

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

$date=Get-Date -Format "yyyy-MM-dd"
$snapshotName=$vmName + $date

$vm=Get-AzVM -ResourceGroupName $rg -Name $vmName

$statusArray=Get-AzVM -ResourceGroupName $rg -Name $vmName -Status
$status=$statusArray.Statuses[1].Code

Write-Output "La maquina $vmName esta en el estado $status al iniciar la toma de la snapshot"

$uriVM=$vm.StorageProfile.OsDisk.ManagedDisk.Id
$uriVMString=$uriVM.ToString()
$snapswap=New-AzSnapshotConfig -SourceUri $uriVMString -Location $location -CreateOption copy -Tag @{FechaCreacion=$date.ToString()}
$snapshotswapName=$vmName + "OSdisk" + $date
$snapshotswap=New-AzSnapshot -Snapshot $snapswap -SnapshotName $snapshotswapName -ResourceGroupName $rg

$datadiskname=$vm.StorageProfile.DataDisks.Name

if($datadiskname)
{
    $datadisk=Get-AzDisk -ResourceGroupName $rg -DiskName $datadiskname
    $uriData=$datadisk.Id
    $uriDataString=$uriData.ToString()
    $snap=New-AzSnapshotConfig -SourceUri $uriDataString -Location $location -CreateOption copy -Tag @{FechaCreacion=$date.ToString()}
    $snapshot=New-AzSnapshot -Snapshot $snap -SnapshotName $snapshotName -ResourceGroupName $rg

    if($snapshot)
    {
        Write-Output "Snapshot $snapshotName creada correctamente"
    }
    else
    {
        Write-Output "Falla al crear snapshot $snapshotName"
    }
}

if($snapshotswap)
{
    Write-Output "Snapshot $snapshotswapName creada correctament"    
    $statusArray=Get-AzVM -ResourceGroupName $rg -Name $vmName -Status
    $status=$statusArray.Statuses[1].Code
    Write-Output "La maquina $vmName esta en el estado $status al finalizar la toma de la snapshot"
}
else
{
    Write-Output "Falla al crear snapshot $snapshotswapName"
    $statusArray=Get-AzVM -ResourceGroupName $rg -Name $vmName -Status
    $status=$statusArray.Statuses[1].Code
    Write-Output "La maquina $vmName esta en el estado $status al fallar la toma de la snapshot"
}
