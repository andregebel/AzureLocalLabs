#region basics
    #Install Management Tools
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica,NetworkATC


    #Define svariables
    $Servers="ASNode1","ASNode2"
    $Stornet1="172.16.1."
    $Stornet2="172.16.2."
    $IP=1 #Start IP
    $StorVLAN1=1
    $StorVLAN2=2
    $ClusterName="ASClus01"
    $ClusterIP="10.0.0.111"
    $WitnessServer="DC"
    $vSwitchName="vSwitch"

    $ResourceGroupName="ASClus01-RG"
    $Location="eastus"

    #check OS Build Number
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
    $ComputersInfo  = Invoke-Command -ComputerName $servers -ScriptBlock {
        Get-ItemProperty -Path $using:RegistryPath
    }
    $ComputersInfo | Select-Object PSComputerName,CurrentBuildNumber,DisplayVersion,UBR
    
    #Update Servers
        # create temporary virtual account to avoid double-hop issue while keeping secrets locally (unlike CredSSP)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
            Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
        } -ErrorAction Ignore
        # Run Windows Update via ComObject.
        Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
            $Searcher = New-Object -ComObject Microsoft.Update.Searcher
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
            IsPresent=1 and DeploymentAction='Uninstallation' or
            IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
            IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
            $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
            $Session = New-Object -ComObject Microsoft.Update.Session
            $Downloader = $Session.CreateUpdateDownloader()
            $Downloader.Updates = $SearchResult
            $Downloader.Download()
            $Installer = New-Object -ComObject Microsoft.Update.Installer
            $Installer.Updates = $SearchResult
            $Result = $Installer.Install()
            $Result
        }
        #remove temporary PSsession config
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Unregister-PSSessionConfiguration -Name 'VirtualAccount'
            Remove-Item -Path $env:TEMP\VirtualAccount.pssc
        }

    #Configure some basic settings
        #Configure Active memory dump
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
            Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
        }

        #Configure high performance power plan
            #set high performance if not VM
            Invoke-Command -ComputerName $servers -ScriptBlock {
                if ((Get-ComputerInfo).CsSystemFamily -ne "Virtual Machine"){
                    powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
                }
            }
            #check settings
            Invoke-Command -ComputerName $servers -ScriptBlock {powercfg /list}

    #Install features
        #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
            if ($result.ExitCode -eq "failed"){
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            }
        }

        #define and install features
        $features="Failover-Clustering","Hyper-V-PowerShell","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features}

        #restart and wait for computers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force
        Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
        #make sure computers are restarted
        Foreach ($Server in $Servers){
            do{$Test= Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
        }

    #Validate version
        #check OS Build Number
        $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
        $ComputersInfo  = Invoke-Command -ComputerName $servers -ScriptBlock {
            Get-ItemProperty -Path $using:RegistryPath
        }
        $ComputersInfo | Select-Object PSComputerName,CurrentBuildNumber,DisplayVersion,UBR
#endregion

#region Configure networking
    Get-Netadapter -CimSession $Servers | Where-Object Status -ne "Up" | Disable-NetAdapter -Confirm:0
 
    $FastestLinkSpeed=(get-netadapter -cimsession $Servers | Where-Object Status -eq Up).Speed | Sort-Object -Descending | Select-Object -First 1
    Get-NetAdapter -CimSession $Servers | Where-Object Status -eq Up | where-object Speed -eq $FastestLinkSpeed | Get-NetAdapterSRIOV -ErrorAction Ignore | Format-Table Name,Description,SriovSupport,Enabled,PSComputerName
 
    $SRIOVSupport=$True
    #If SR-IOV is configured to $True, create vSwitch with SR-IOV
    Invoke-Command -ComputerName $servers -ScriptBlock {
        $FastestLinkSpeed=(get-netadapter | Where-Object Status -eq Up).Speed | Sort-Object -Descending | Select-Object -First 1
        $NetAdapters=Get-NetAdapter | Where-Object Status -eq Up | Where-Object Speed -eq $FastestLinkSpeed | Sort-Object Name
        if ($using:SRIOVSupport){
            New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName $NetAdapters.Name
        }else{
            New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -NetAdapterName $NetAdapters.Name
        }
    }
 
    Get-VMSwitch -CimSession $Servers | Select-Object Name,IOV*,ComputerName
 
    #rename Management vNIC first
    Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName -NewName Management -CimSession $Servers


    foreach ($Server in $Servers){
        #add SMB vNICs (number depends on how many NICs are connected to vSwitch)
        $SMBvNICsCount=(Get-VMSwitch -CimSession $Server -Name $vSwitchName).NetAdapterInterfaceDescriptions.Count
        foreach ($number in (1..$SMBvNICsCount)){
            $TwoDigitNumber="{0:D2}" -f $Number
            Add-VMNetworkAdapter -ManagementOS -Name "SMB$TwoDigitNumber" -SwitchName $vSwitchName -CimSession $Server
        }
    }
 
    Get-VMNetworkAdapter -CimSession $Servers -ManagementOS

    #Configure IP Addresses
    foreach ($Server in $Servers){
        $SMBvNICsCount=(Get-VMSwitch -CimSession $Server -Name $vSwitchName).NetAdapterInterfaceDescriptions.Count
        foreach ($number in (1..$SMBvNICsCount)){
            $TwoDigitNumber="{0:D2}" -f $Number
            if ($number % 2 -eq 1){
                New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB$TwoDigitNumber)" -CimSession $Server -PrefixLength 24
            }else{
                New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB$TwoDigitNumber)" -CimSession $Server -PrefixLength 24
                $IP++
            }
        }
    }
    
    #Configure VLANs
    #configure Odds and Evens for VLAN1 and VLAN2
    foreach ($Server in $Servers){
        $NetAdapters=Get-VMNetworkAdapter -CimSession $server -ManagementOS -Name *SMB* | Sort-Object Name
        $i=1
        foreach ($NetAdapter in $NetAdapters){
            if (($i % 2) -eq 1){
                Set-VMNetworkAdapterVlan -VMNetworkAdapterName $NetAdapter.Name -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $Server
                $i++
            }else{
                Set-VMNetworkAdapterVlan -VMNetworkAdapterName $NetAdapter.Name -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $Server
                $i++
            }
        }
    }
    #Restart each host vNIC adapter so that the Vlan is active.
    Get-NetAdapter -CimSession $Servers -Name "vEthernet (SMB*)" | Restart-NetAdapter

    #Configure vNICs to pNICs mapping
    #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        #grab adapter names
        $physicaladapternames=(get-vmswitch $using:vSwitchName).NetAdapterInterfaceDescriptions
        #map pNIC and vNICs
        $vmNetAdapters=Get-VMNetworkAdapter -Name "SMB*" -ManagementOS
        $i=0
        foreach ($vmNetAdapter in $vmNetAdapters){
            $TwoDigitNumber="{0:D2}" -f ($i+1)
            Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB$TwoDigitNumber" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapternames[$i]).name
            $i++
        }
    }
    
    #Configure DCB
        #Install DCB
        Invoke-Command -ComputerName $Servers -ScriptBlock {Install-WindowsFeature -Name "Data-Center-Bridging"} 

        ##Configure QoS
        New-NetQosPolicy "SMB"       -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $servers
        New-NetQosPolicy "ClusterHB" -Cluster                         -PriorityValue8021Action 7 -CimSession $servers
        New-NetQosPolicy "Default"   -Default                         -PriorityValue8021Action 0 -CimSession $servers

        #Turn on Flow Control for SMB
        Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}

        #Disable flow control for other traffic than 3 (pause frames should go only from prio 3)
        Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}

        #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
        Invoke-Command -ComputerName $servers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}

        #Configure IeeePriorityTag
        #IeePriorityTag needs to be On if you want tag your nonRDMA traffic for QoS. Can be off if you use adapters that pass vSwitch (both SR-IOV and RDMA bypasses vSwitch)
        Invoke-Command -ComputerName $servers -ScriptBlock {Set-VMNetworkAdapter -ManagementOS -Name "SMB*" -IeeePriorityTag on}

        #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch
        Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}

        #Create a Traffic class and give SMB Direct 50% of the bandwidth minimum. The name of the class will be "SMB".
        #This value needs to match physical switch configuration. Value might vary based on your needs.
        #If connected directly (in 2 node configuration) skip this step.
        Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB"       -Priority 3 -BandwidthPercentage 50 -Algorithm ETS}
        Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "ClusterHB" -Priority 7 -BandwidthPercentage 1 -Algorithm ETS}

#endregion

#region Validate networking
    #validate vSwitch
    Get-VMSwitch -CimSession $servers
    #validate vNICs
    Get-VMNetworkAdapter -CimSession $servers -ManagementOS
    #validate vNICs to pNICs mapping
    Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | Format-Table ComputerName,NetAdapterName,ParentAdapter
    #validate JumboFrames setting
    Get-NetAdapterAdvancedProperty -CimSession $servers -DisplayName "Jumbo Packet"
    #verify RDMA settings
    Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | Format-Table systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
    #validate if VLANs were set
    Get-VMNetworkAdapterVlan -CimSession $Servers -ManagementOS
    #verify ip config 
    Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputerName | Format-Table PSComputerName,interfacealias,ipaddress -AutoSize -GroupBy pscomputername
    #Validate DCBX setting
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName
    #validate flow control setting
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosFlowControl} | Sort-Object  -Property PSComputername | Format-Table PSComputerName,Priority,Enabled -GroupBy PSComputerName
    #validate QoS Traffic Classes
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosTrafficClass} |Sort-Object PSComputerName |Select-Object PSComputerName,Name,PriorityFriendly,Bandwidth
#endregion

#region create cluster
    #remove USB NICs from cluster networks
    Invoke-Command -computername $Servers -scriptblock {
        #New-Item -Path HKLM:\system\currentcontrolset\services\clussvc
        New-Item -Path HKLM:\system\currentcontrolset\services\clussvc\parameters
        New-ItemProperty -Path HKLM:\system\currentcontrolset\services\clussvc\parameters -Name ExcludeAdaptersByDescription -Value "Remote NDIS Compatible Device"
        #Get-ItemProperty -Path HKLM:\system\currentcontrolset\services\clussvc\parameters -Name ExcludeAdaptersByDescription | Format-List ExcludeAdaptersByDescription
    }

    #Test cluster first
    Test-Cluster -Node $servers -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"

    #Traditional Cluster with Static IP
    New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
    #Cluster with IP from DHCP
    #New-Cluster -Name $ClusterName -Node $servers
    #Cluster with Distributed Domain Name
    #New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"

#endregion

#region configure cluster
    #Configure Witness
        #Create new directory
            $WitnessName=$Clustername+"Witness"
            Invoke-Command -ComputerName $WitnessServer -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            $accounts=@()
            $accounts+="corp\$ClusterName$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession $WitnessServer
        #Set NTFS permissions 
            Invoke-Command -ComputerName $WitnessServer -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
        #Set Quorum
            Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\$WitnessServer\$WitnessName"
    
    #rename networks
    (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="SMB01"
    (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="SMB02"

    #Rename Management Network
    (Get-ClusterNetwork -Cluster $clustername | Where-Object Role -eq "ClusterAndClient").Name="Management"

    #Rename and Configure USB NICs
    $USBNics=get-netadapter -CimSession $Servers -InterfaceDescription "Remote NDIS Compatible Device" -ErrorAction Ignore
    if ($USBNics){
        $Network=(Get-ClusterNetworkInterface -Cluster $ClusterName | Where-Object Adapter -eq "Remote NDIS Compatible Device").Network | Select-Object -Unique
        $Network.Name="iDRAC"
        $Network.Role="none"
    }

    #configure Live Migration 
    Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Role -ne "Cluster"}).ID))
    Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers

    #Configure SMB Bandwidth Limits for Live Migration https://techcommunity.microsoft.com/t5/Failover-Clustering/Optimizing-Hyper-V-Live-Migrations-on-an-Hyperconverged/ba-p/396609
        #install feature
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name "FS-SMBBW"}
        #Calculate 40% of capacity of NICs in vSwitch (considering 2 NICs, if 1 fails, it will not consume all bandwith, therefore 40%)
        $Adapters=(Get-VMSwitch -CimSession $Servers[0]).NetAdapterInterfaceDescriptions
        $BytesPerSecond=((Get-NetAdapter -CimSession $Servers[0] -InterfaceDescription $adapters).TransmitLinkSpeed | Measure-Object -Sum).Sum/8
        Set-SmbBandwidthLimit -Category LiveMigration -BytesPerSecond ($BytesPerSecond*0.4) -CimSession $Servers
#endregion

#region configure s2d
    $DeletePool=$false
    #Wipe disks
    if ($DeletePool){
        #Grab pool
        $StoragePool=Get-StoragePool -CimSession $ClusterName -IsPrimordial $False -ErrorAction Ignore
        #Wipe Virtual disks if any
        if ($StoragePool){
            $Clusterresource=Get-ClusterResource -Cluster $ClusterName | Where-Object ResourceType -eq "Storage Pool"
            if ($Clusterresource){
                $Clusterresource | Remove-ClusterResource -Force
            }
            $StoragePool | Set-StoragePool -IsReadOnly $False
            $VirtualDisks=$StoragePool | Get-VirtualDisk -ErrorAction Ignore
            #Remove Disks
            if ($VirtualDisks){
                $VirtualDisks | Remove-VirtualDisk -Confirm:0
            }
            #Remove Pool
            $StoragePool | Remove-StoragePool -Confirm:0
        }
        #Reset disks (to clear spaces metadata)
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Get-PhysicalDisk -CanPool $True | Reset-PhysicalDisk
        }
    }

    #Enable-ClusterS2D
    Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose
    
    #create volumes
    #calculate reserve
    $pool=Get-StoragePool -CimSession $clustername -FriendlyName s2D*
    $HDDCapacity= ($pool |Get-PhysicalDisk -CimSession $clustername | where-object mediatype -eq HDD | Measure-Object -Property Size -Sum).Sum
    $HDDMaxSize=  ($pool |Get-PhysicalDisk -CimSession $clustername | where-object mediatype -eq HDD | Measure-Object -Property Size -Maximum).Maximum
    $SSDCapacity= ($pool |Get-PhysicalDisk -CimSession $clustername | where-object mediatype -eq SSD | where-object usage -ne journal | Measure-Object -Property Size -Sum).Sum
    $SSDMaxSize=  ($pool |Get-PhysicalDisk -CimSession $clustername | where-object mediatype -eq SSD | where-object usage -ne journal | Measure-Object -Property Size -Maximum).Maximum

    $numberofNodes=(Get-ClusterNode -Cluster $clustername).count
    if ($numberofNodes -eq 2){
        if ($SSDCapacity){
        $SSDCapacityToUse=$SSDCapacity-($numberofNodes*$SSDMaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
        $sizeofvolumeonSSDs=$SSDCapacityToUse/2/$numberofNodes
        }
        if ($HDDCapacity){
        $HDDCapacityToUse=$HDDCapacity-($numberofNodes*$HDDMaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
        $sizeofvolumeonHDDs=$HDDCapacityToUse/2/$numberofNodes
        }
    }else{
        if ($SSDCapacity){
        $SSDCapacityToUse=$SSDCapacity-($numberofNodes*$SSDMaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
        $sizeofvolumeonSSDs=$SSDCapacityToUse/3/$numberofNodes
        }
        if ($HDDCapacity){
        $HDDCapacityToUse=$HDDCapacity-($numberofNodes*$HDDMaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
        $sizeofvolumeonHDDs=$HDDCapacityToUse/3/$numberofNodes
        }
    }
    $sizeofvolumeonSSDs/1TB
    $sizeofvolumeonHDDs/1TB
    
    $ThinVolumes=$True
    #configure Pool to default to Thin Provisioning
    if ($ThinVolumes){
        Set-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" -ProvisioningTypeDefault Thin
    }
    #create volumes
    1..$numberofNodes | ForEach-Object {
        if ($sizeofvolumeonHDDs){
            New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size $sizeofvolumeonHDDs -FriendlyName "Volume$_" -MediaType HDD
        }
        if ($sizeofvolumeonSSDs){
            New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size $sizeofvolumeonSSDs -FriendlyName "Volume$_" -MediaType SSD
        }
    }
#endregion

#region register Azure Stack HCI to Azure
    #download Azure module
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)){
        Install-Module -Name Az.StackHCI -Force
    }

    #login to azure
    #download Azure module
    if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
        Install-Module -Name Az.Accounts -Force
    }
    Login-AzAccount -UseDeviceAuthentication

    $subscriptionID=(Get-AzContext).subscription.id

    if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force
    }
    #create RG
    If (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    }

    #Register AZSHCi without prompting for creds
    $armTokenItemResource = "https://management.core.windows.net/"
    $graphTokenItemResource = "https://graph.windows.net/"
    $azContext = Get-AzContext
    $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
    $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
    $id = $azContext.Account.Id
    #Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id
    Register-AzStackHCI -Region $Location -SubscriptionID $subscriptionID -ComputerName  $ClusterName -ArmAccessToken $armToken -AccountId $id -ResourceName $ClusterName -ResourceGroupName $ResourceGroupName
 
#endregion

#region add some blank VMs
    $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
    foreach ($CSV in $CSVs){
        $CSV=$CSV.Replace("Cluster Virtual Disk (","").Replace(")","")
        1..3 | ForEach-Object {
            $VMName="TestVM$($CSV)_$_"
            Invoke-Command -ComputerName (Get-ClusterNode -Cluster $ClusterName).name[0] -ScriptBlock {
                New-VM -Name $using:VMName -NewVHDPath "c:\ClusterStorage\$using:CSV\$using:VMName\Virtual Hard Disks\$using:VMName.vhdx" -MemoryStartupBytes 32MB -NewVHDSizeBytes 32GB -Generation 2 -Path "c:\ClusterStorage\$using:CSV\" -SwitchName $using:vSwitchName
                Start-VM -Name $using:VMName
            }
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
        }
    }
#endregion
