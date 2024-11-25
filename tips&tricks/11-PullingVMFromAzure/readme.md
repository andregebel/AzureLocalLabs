### Work in progress ###
<!-- TOC -->

- [Pull required modules, files...](#pull-required-modules-files)
- [Create some VM in Azure first](#create-some-vm-in-azure-first)
- [Query VM and create it onprem using AZ](#query-vm-and-create-it-onprem-using-az)

<!-- /TOC -->Microsoft SDKs\Azure\CLI2\wbin')


#login to Azure

    if (-not (Get-AzContext)){
        Login-AzAccount -UseDeviceAuthentication
    }
    az login --use-device-code

```

## Create some VM in Azure first

Howto: https://learn.microsoft.com/en-us/azure/virtual-machines/windows/tutorial-manage-vm

```PowerShell
New-AzResourceGroup -ResourceGroupName "myResourceGroupVM" -Location "EastUS"
$cred = Get-Credential
New-AzVm -ResourceGroupName "myResourceGroupVM" -Name "myVM" -Location "EastUS" -VirtualNetworkName "myVnet" -SubnetName "mySubnet" -SecurityGroupName "myNetworkSecurityGroup" -PublicIpAddressName "myPublicIpAddress" -ImageName "MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition-hotpatch-smalldisk:latest" -Credential $cred
 
```

## Query VM and create it onprem using AZ

```PowerShell
$VMs=Get-AZVM | Out-GridView -OutputMode Multiple -Title "Please select VMs to pull from Azure"

foreach ($VM in $VMs){
    $Resource=(Get-AzResource -ResourceId $VM.Id)

    #grab OS disk
    $Disk=Get-AzDisk  | Where-Object ID -Eq $Resource.Properties.storageProfile.osdisk.managedDisk.id

    #grant access
     $output=$Disk |Grant-AzDiskAccess -Access Read -DurationInSecond 3600
     
}




```