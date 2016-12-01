# Use ONLY with CPS Premium FRU guide
# Applies to: CPS Premium 1.0 Update 1611 

$StorageNodes, 
$PhysicalDiskStorageNodeView = "" 
$DiskErrorCount = 0 
$StorageNodeErrorCount = 0 

$StorageNodes = Get-StorageNode 

Foreach($storagenode in $StorageNodes) 
{ 
    $PhysicalDiskStorageNodeView = Get-PhysicalDiskStorageNodeView -StorageNode $StorageNode 
    $ErrorCount=0 

    foreach($PhysicalDiskView in $PhysicalDiskStorageNodeView) 
    { 
        if($PhysicalDiskView.IsMpioEnabled -eq $False -or $PhysicalDiskView.PathState[0] -ne "Active/Optimized" -or $PhysicalDiskView.PathState[1] -ne "Active/Optimized") 
        { 
            $DiskName = "PhysicalDisk" + $PhysicalDiskView.DiskNumber  
            if((Get-PhysicalDisk -FriendlyName $DiskName).BusType -eq "SAS") 
            { 
                $ErrorCount++ 
                Write-Host "!!!ERROR!!!  MPIO query status failed for Disk Number " $PhysicalDiskView.DiskNumber -ForegroundColor Red -BackgroundColor Black 
                Write-Output $PhysicalDiskView | fl * -DisplayError 
            } 
        } 
    } 

    if($ErrorCount -eq 0) 
    { 

        Write-Host "Successfully verfied multi paths for " $PhysicalDiskStorageNodeView.Count " disks on storage node " $StorageNode.Name -ForegroundColor Cyan 
    } 
    else  
    { 
        $StorageNodeErrorCount++ 
        Write-Host "Failed to verify " $ErrorCount " multi paths for storage node " $StorageNode.Name -ForegroundColor Red -BackgroundColor Black 
    } 
} 

    if($StorageNodeErrorCount -eq 0) 
    { 
        Write-Host "Successfully verified multi paths for all storage nodes" -ForegroundColor Cyan 
    } 
    else  
    { 
        $StorageNodeErrorCount++ 
        Write-Host "Failure in verifying disk(s) on " $StorageNodeErrorCount "/" $StorageNodes.count " StorageNode nodes " -ForegroundColor Red -BackgroundColor Black 
    } 
