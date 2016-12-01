# Use ONLY with CPS Premium FRU guide
# Applies to: CPS Premium 1.0 Update 1611 

{
#region Step 3: Identify the name of the domain controller that is down 
$DCs = (Get-AdDomain).ReplicaDirectoryServers 
$DCs
$DCs | %{if(-not (Invoke-Command $_ {$true} -ErrorAction SilentlyContinue)) {write-error "$_ is down"}} 
$NewDomainControllerFQDN = "SA24DC1.D25SAN24.nttest.microsoft.com"
$NewDomainControllerName = "SA24DC1"
#endregion
#region Step 4: Identify the IP address of the down domain controller 
$ipv4addresses= @()
$DCs | %{if($_ -ne $NewDomainControllerFQDN) { $ipv4addresses+=icm $_ {$IPV4Address = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).addresslist | ? AddressFamily -eq 'InterNetwork'; $IPV4Address.IPAddressToString
}}}
$ipv4addresses
$DCIPAddress = '10.60.193.7' 
#endregion
#region Step 5: Determine if you need to create DHCP scopes and configure DHCP failover 
$LiveDCMachineName = 'SA24DC2.D25SAN24.nttest.microsoft.com'
$scopeHash = @{}
$DCs | %{ if($_ -ne $NewDomainControllerFQDN) { $scope = icm $_ {Get-DhcpServerv4Scope}; $scopeHash[$_]=$scope}}
$isDHCPScopeRequired = $false
$DcToUse = $null
$scopeHash.Keys | %{if($scopeHash[$_] –eq $null) {$isDHCPScopeRequired = $true} else {$DCToUse = $_}} 
$LiveDCMachineName = $DCToUse 
$isDHCPScopeRequired
#endregion
#region Step 6: Set additional variables that are needed for the scripts 
$NewNodeNameFQDN = "SA24R1MS22-1.D25SAN24.nttest.microsoft.com"
$DomainFQDN = "D25SAN24.nttest.microsoft.com" 

$secpasswd = ConvertTo-SecureString “!!123abc” -AsPlainText -Force
$EnterpriseAdminCredential = New-Object System.Management.Automation.PSCredential (“d25san24\cps-fruadminntr”, $secpasswd)

$FullServerVHDPathFromVMMLibraryServer = "\\SA24-FS.D25SAN24.nttest.microsoft.com\ManagementGuestLibrary\VHDs\WindowsServer2012R2.vhdx"
#endregion
#region Step 7: Ensure that the operations master roles are owned by active domain controllers 

$ErrorActionPreference = "Stop"
$domain = invoke-command -ComputerName $LiveDCMachineName { Get-ADDomain } -Credential $EnterpriseAdminCredential
$roles = @()
$forest = invoke-command -ComputerName $LiveDCMachineName { Get-ADForest } -Credential $EnterpriseAdminCredential
if($domain.PDCEmulator -eq $NewDomainControllerFQDN) { $roles+="PDCEmulator"}
if($domain.InfrastructureMaster -eq $NewDomainControllerFQDN) {$roles+="InfraStructureMaster"}
if($domain.RIDMaster -eq $NewDomainControllerFQDN) {$roles+="RIDMaster"}
if($forest.SchemaMaster -eq $NewDomainControllerFQDN) {$roles+= "SchemaMaster"}
if($forest.DomainNamingMaster -eq $NewDomainControllerFQDN) {$roles+="DomainNamingMaster"}
if($roles.Count -gt 0) {Invoke-Command -ComputerName $LiveDCMachineName { Get-ADDomainController -Server localhost | Move-ADDirectoryServerOperationMasterRole -OperationMasterRole $using:roles -Confirm:$false –Force} -Credential $EnterpriseAdminCredential}
if($roles.Count -gt 0) { Write-Output "FSMO roles - $roles - have been moved to $LiveDCMachineName" }
#endregion
#region Step 8: Clean up Active Directory metadata for the missing domain controller 
$DC = Invoke-command -ComputerName $LiveDCMachineName { Get-ADDomainController }  -Credential $EnterpriseAdminCredential 
$ServerDN = $DC.ServerObjectDN
$ServerDN
$ServerDN = "CN=SA24DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=D25SAN24,DC=nttest,DC=microsoft,DC=com"
$command = 'ntdsutil "metadata cleanup" "remove selected server '+ $ServerDN + '" "q" "q"'
Invoke-Command -ComputerName $LiveDCMachineName {Invoke-Expression $using:command} -Credential $EnterpriseAdminCredential
#endregion
#region Step 9: Create the new domain controller 
copy-item "\\$LiveDCMachineName\C$\unattend.xml" $env:TEMP -Force
notepad $env:TEMP\unattend.xml
$LocalAdminUserName = "Administrator"
$localAdminPassword = "!!123abc"
$secureString = ConvertTo-SecureString $localAdminPassword -AsPlainText -Force    
$localAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $LocalAdminUserName, $secureString 
$adHostSession = New-PSSession -ComputerName $NewNodeNameFQDN -Credential $EnterpriseAdminCredential 
$adHostSystemDriveLetter = Invoke-Command -Session $adHostSession {Get-Volume | where FileSystemLabel -like 'CCNode_OS' | select -ExpandProperty DriveLetter} 
Get-PSDrive | ? Name -eq "AD" | Remove-PSDrive
$NewNodeName = $NewNodeNameFQDN.Split(".")[0] 
$adDrive = New-PSDrive -PSProvider FileSystem -Root  “\\$NewNodeName\$adHostSystemDriveLetter`$"  -Credential $EnterpriseAdminCredential -Name "AD" 
$adPath = "AD:\CloudBuilder\VMs\AD"
$adPrimaryPath = "$adPath\$NewDomainControllerName"
$adVhdFolderPath = "$adPrimaryPath\VHD"
$adVMFolderPath = "$adPrimaryPath\VM" 
if (Test-Path $adPath) {
            Remove-Item $adPath -Recurse -Force
        } 
$null = mkdir  "$adVhdFolderPath"  -Force
$null = mkdir  "$adVMFolderPath"  -Force
$adTargetVhdPath = "$adPath\$NewDomainControllerName\VHD\$NewDomainControllerName.vhdx"
$adTargetVhdPathLocal = $adTargetVhdPath.Replace('AD:', $adHostSystemDriveLetter + ':')
Write-Output "Copying the VHD from the library server to $adTargetVhdPathLocal on $NewNodeNameFQDN" 
Copy-Item $FullServerVHDPathFromVMMLibraryServer $adTargetVhdPath –Force

Invoke-Command -Session $adHostSession{
         $AddWindowsFeatureResult = Install-WindowsFeature -Vhd $using:adTargetVhdPathLocal -Name 'DHCP', 'DNS', 'AD-Domain-Services' -IncludeAllSubFeature -IncludeManagementTools
         $AddWindowsFeatureResult.Success
        }

$adUnattendPath = "$adVhdFolderPath\unattend.xml" 
$adUnattendPathLocal = $adUnattendPath.Replace('AD:', 
$adHostSystemDriveLetter + ':') 
Copy-Item $env:TEMP\unattend.xml $adUnattendPath 
Invoke-Command -Session $adHostSession {
            $mountedImages = Get-WindowsImage -Mounted -Verbose:$false
            if ($mountedImages) {
                $null = $mountedImages | % { Dismount-WindowsImage -Path $_.MountPath -Discard -Verbose:$false}
            }
        }
$mountPath = Invoke-Command -Session $adHostSession {
            $mountPath = [IO.Path]::GetTempFileName()
            Remove-Item $mountPath -Recurse -Force
            $null = mkdir $mountPath -Force
            return $mountPath
        } 
Invoke-Command -Session $adHostSession {
            $null = Mount-WindowsImage -ImagePath $using:adTargetVhdPathLocal -Path $mountPath -Index 1 -Verbose:$false
        }
Invoke-Command -Session $adHostSession {
            Move-Item $using:adUnattendPathLocal $mountPath
        }
Invoke-Command -Session $adHostSession {
            $null = Dismount-WindowsImage -Path $mountPath -Save -Verbose:$false
        }

$adStorageVhdPathLocal = $adTargetVhdPathLocal.Replace('.vhdx', '.Storage.vhdx') 
$storageVhd = Invoke-Command -Session $adHostSession {
  New-VHD -Path  $using:adStorageVhdPathLocal -SizeBytes 4096MB -Fixed
 }
$storageVhdId = $storageVhd.DiskIdentifier
$global:storageVHDSize = $storageVhd.Size
$adBackupVhdPathLocal = $adTargetVhdPathLocal.Replace('.vhdx', '.Backup.vhdx') 
$backupVhd = Invoke-Command -Session $adHostSession {            
   New-VHD -Path $using:adBackupVhdPathLocal -SizeBytes 65GB -Dynamic
   }
$backupVhdId = $backupVhd.DiskIdentifier
$global:backupVhdSize = $backupVhd.Size

if($LiveDCMachineName.Contains("."))
{
  $LiveDCMachineNameOnly = $LiveDCMachineName.Split(".")[0]
}
else
{
  $LiveDCMachineNameOnly =  $LiveDCMachineName
}
$property = Invoke-Command -ComputerName $LiveDCMachineName {
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'
  } -Credential $EnterpriseAdminCredential
$vmProperties = Invoke-Command -ComputerName $property.HostName {
    $vm = get-vm -Name $using:LiveDCMachineNameOnly;        
    $vm.NetworkAdapters;$vm.NetworkAdapters.VlanSetting
  } -Credential $EnterpriseAdminCredential
$adVMPath = $adVMFolderPath.Replace('AD:',$adHostSystemDriveLetter + ':') 
$adVhdPath = $adTargetVhdPathLocal
$adVMMemory = 4096MB 
$adVMSwitchName = $vmProperties[0].SwitchName
$adVMProcessorCount = 2
$adVMDynamicMemory = $false
$adVMVLanId = $vmProperties[1].AccessVlanId 

Invoke-Command –Session $adHostSession {
     $vm = New-VM –Name $using:NewDomainControllerName –Path $using:adVMPath –VHDPath $using:adVhdPath –MemoryStartupBytes $using:adVMMemory –BootDevice VHD –SwitchName $using:adVMSwitchName
    }
Invoke-Command –Session $adHostSession {
     Set-VM –VM $vm –ProcessorCount $using:adVMProcessorCount –AutomaticStartAction Start –DynamicMemory:$using:adVMDynamicMemory –Confirm:$false
    }
Write-Output "Adding the new VHDs on the VM for storage and backup."
Invoke-Command –Session $adHostSession {
 Add-VMHardDiskDrive –VM $vm –Path $using:adStorageVhdPathLocal –Confirm:$false
}
Invoke-Command –Session $adHostSession {
  Add-VMHardDiskDrive –VM $vm –Path $using:adBackupVhdPathLocal –Confirm:$false
}
Invoke-Command –Session $adHostSession {
      Set-VMNetworkAdapterVlan –VM $vm –VlanId $using:adVMVLanId –Access –Confirm:$false
  }
Write-Output "Starting the new VM."
Invoke-Command –Session $adHostSession {
    Start-VM –VM $vm –Confirm:$false
}
Invoke-Command -ComputerName $DCIPaddress {$true} -Credential $localAdminCredential 

function Initialize-VirtualDrive
{
    param (
        [Parameter(Mandatory=$true)]
        [UInt64]
        $sizeIdentifier,

        [Parameter(Mandatory=$true)]
        $cimSession
    )
    $disk = Get-Disk -CimSession $cimSession | ? Size -eq $sizeIdentifier
    Set-Disk -Number $disk.Number -IsOffline:$false -CimSession $cimSession
    Set-Disk -Number $disk.Number -IsReadOnly:$false -CimSession $cimSession
    Initialize-Disk -Number $disk.Number -PartitionStyle MBR -CimSession $cimSession -ErrorAction SilentlyContinue
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter -CimSession $cimSession
    Start-Sleep 10
    Set-Disk -Number $disk.Number -IsReadOnly:$false -CimSession $cimSession
    $success = $false
    $endTime = [DateTime]::Now.AddSeconds(45)
    $exception = $null
    while(($success -ne $true) -and ([DateTime]::Now -lt $endTime))
    {
        try
        {
            $volume = Format-Volume -Partition $partition -FileSystem NTFS -CimSession $cimSession -Confirm:$false
            $success = $true
        }
        catch
        {
            $success = $false
            $exception = $_
        }
    }
    if($success -ne $true)
    {
        throw $exception 
    }
    return $volume.DriveLetter
} 

$adVmCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ".\$localAdminUsername",$secureString
$adCimSession = New-CimSession $DCIPaddress -Credential $adVmCredential
Write-Output "Initialize and format storage disk on AD VM."
$global:storageDriveLetter = Initialize-VirtualDrive $global:storageVHDSize -cimSession $adCimSession
Write-Output "Initialize and format backup disk on AD VM."
$global:backupDriveLetter = Initialize-VirtualDrive $global:backupVHDSize -cimSession $adCimSession 

$DNSServerAddress = Invoke-Command $LiveDCMachineName {Get-DnsClientServerAddress} -Credential $EnterpriseAdminCredential
$ServerAddresses = $DNSServerAddress[1].ServerAddresses
Invoke-Command $DCIPaddress {Set-DnsClientServerAddress -InterfaceAlias * -ServerAddresses $using:ServerAddresses} -Credential $adVmCredential

$adSession = New-PSSession $DCIPaddress -Credential $adVmCredential
$databasePath = "$global:storageDriveLetter`:\NTDS"
$systemVolumePath = "$global:storageDriveLetter`:\SYSVOL"    
Invoke-Command -Session $adSession {
    $null = New-Item -Path $using:databasePath -ItemType Directory -Force
    $null = New-Item -Path $using:systemVolumePath -ItemType Directory -Force
    }

$safeModeAdministratorPasswordString = "!!123abc" 
$safeModeAdministratorPassword = ConvertTo-SecureString -Force -AsPlainText -String $safeModeAdministratorPasswordString 
Invoke-Command $adSession { Install-ADDSDomainController –domainName $using:DomainFQDN -credential $using:EnterpriseAdminCredential -safeModeAdministratorPassword $using:safeModeAdministratorPassword -InstallDNS -DatabasePath $using:databasePath -LogPath $using:databasePath –SysvolPath $using:systemVolumePath -NoRebootOnCompletion -Force}

Get-PSSession | remove-pssession -ErrorAction SilentlyContinue
Get-CimSession | Remove-CimSession -ErrorAction SilentlyContinue
$adCimsession = New-CimSession -ComputerName $DCIPaddress –Credential $adVMCredential
$OldTime =  Invoke-Command -ComputerName $DCIPaddress {[DateTime]::Now} -Credential $adVMCredential
$null = Invoke-CimMethod -ClassName Win32_OperatingSystem -MethodName Win32Shutdown -Arguments @{Flags=[int32]6} -CimSession $script:adCimSession -Verbose:$false

Get-CimSession | Remove-CimSession -ErrorAction SilentlyContinue
$adCimsession = New-CimSession -ComputerName $DCIPaddress -Credential $EnterpriseAdminCredential
$adCimsession

$newOs = Get-CimInstance -CimSession $adCimsession –ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if($newOs.LastBootUpTime -gt $OldTime)
{
   $true
}

Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
Get-CimSession | Remove-CimSession -ErrorAction SilentlyContinue

Get-ADDomainController -Server $NewDomainControllerName -Credential $EnterpriseAdminCredential 
$DCs = (Get-AdDomain).ReplicaDirectoryServers 
$DCs 

Get-WSManCredSSP  
$credsspRegistryKey = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" 
$null = New-Item -Path $credsspRegistryKey -Force 
$null = New-ItemProperty -Path $credsspRegistryKey -Name AllowFreshCredentials -Value 1 -PropertyType DWord -Force 
$null = New-ItemProperty -Path $credsspRegistryKey -Name AllowFreshCredentialsWhenNTLMOnly -Value 1 -PropertyType DWord -Force 
$null = New-ItemProperty -Path $credsspRegistryKey -Name ConcatenateDefaults_AllowFresh -Value 1 -PropertyType DWord -Force 
$null = New-ItemProperty -Path $credsspRegistryKey -Name ConcatenateDefaults_AllowFreshNTLMOnly -Value 1 -PropertyType DWord -Force 
$null = New-Item -Path "$credsspRegistryKey\AllowFreshCredentials" -Force 
$null = New-ItemProperty -Path "$credsspRegistryKey\AllowFreshCredentials" -Name 1 -Value wsman/* -Force 
$null = New-Item -Path "$credsspRegistryKey\AllowFreshCredentialsWhenNTLMOnly" -Force 
$null = New-ItemProperty -Path "$credsspRegistryKey\AllowFreshCredentialsWhenNTLMOnly" -Name 1 -Value wsman/* -Force 
Set-Item WSMan:\localhost\Client\Auth\CredSSP $true -Force  

Invoke-Command $LiveDCMachineName {get-wsmancredssp} -Credential $EnterpriseAdminCredential  
Invoke-Command -ComputerName $LiveDCMachineName –Credential $EnterpriseAdminCredential -ScriptBlock { 
        Set-Item WSMan:\localhost\Service\Auth\CredSSP $true –Force }

if($isDHCPScopeRequired -eq $null) 
{ 
    Write-Error "The variable isDHCPScopeRequired is not set. It should have been set in the current powershell session from Main step 5 - To determine if we need to create DHCP scopes and configure DHCP failover in the new DC above. Please re-run that step before executing this" 
}  

if($LiveDCMachineName.Contains(".")) 
{ 
    $LiveDCMachineNameOnly = $LiveDCMachineName.Split(".")[0] 
} 
else 
{ 
    $LiveDCMachineNameOnly =  $LiveDCMachineName 
}  

if($isDHCPScopeRequired){    
   $IPV4Address = [System.Net.Dns]::GetHostEntry($LiveDCMachineName).addresslist | ? AddressFamily -eq 'InterNetwork'  
   $LiveDCIpAddress = $IPV4Address.IPAddressToString             
   $LiveDCCimCredSSPSession =  New-CimSession -ComputerName $LiveDCMachineName -Credential $EnterpriseAdminCredential -Authentication CredSsp  
   $dhcpScopes = Get-DhcpServerv4Scope -CimSession $LiveDCCimCredSSPSession 
   $failOver = Get-DhcpServerv4Failover -CimSession $LiveDCCimCredSSPSession 
   $failover | %{if($_.ScopeId -contains $dhcpScopes[0].ScopeId) { $_ | Remove-DhcpServerv4Failover -Force -Confirm:$false}} 
   $failoverParameters = @{ 
                Name = "$LiveDCMachineNameOnly-$NewDomainControllerName" 
                ScopeID = $dhcpScopes[0].ScopeId 
                ComputerName = $LiveDCIpAddress 
                PartnerServer = $DCIPaddress 
                AutoStateTransition = $true 
                StateSwitchInterval = ([TimeSpan]::FromSeconds(5)) 
                ServerRole = 'Active' 
    } 
   Add-DhcpServerv4Failover @failoverParameters -CimSession $LiveDCCimCredSSPSession 
   foreach ($dhcpScope in ($dhcpScopes | Select-Object -Skip 1)) { 
        Add-DhcpServerv4FailoverScope -Name $failoverParameters.Name -ScopeId $dhcpScope.ScopeId -CimSession $LiveDCCimCredSSPSession 
   } 
   $partnerDhcpServerCimSession = New-CimSession $DCIPAddress -Credential $EnterpriseAdminCredential         
   Add-DhcpServerInDC -CimSession $partnerDhcpServerCimSession -Confirm:$false 
}  
else 
{ 
    Write-Verbose "No DHCP failover setting required in this setup" 
}  

Get-PSSession | remove-pssession -ErrorAction SilentlyContinue 
Get-CimSession | Remove-CimSession -ErrorAction SilentlyContinue

Set-Item WSMan:\localhost\Client\Auth\CredSSP $false -Force 
$credsspRegistryKey = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" 
if (Test-Path $credsspRegistryKey) { 
        Remove-Item $credsspRegistryKey -Recurse -Force 
    } 
Invoke-Command -ComputerName $LiveDCMachineName –Credential $EnterpriseAdminCredential -ScriptBlock { 
        Set-Item WSMan:\localhost\Service\Auth\CredSSP $false –Force 
} 
#endregion
}