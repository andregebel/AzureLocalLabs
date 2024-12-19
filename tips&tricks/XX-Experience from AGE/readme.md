Recently I learned, that [Microsoft Documentation](https://learn.microsoft.com/en-us/azure-stack/hci/concepts/firewall-requirements) is/was missing some Informations


## Management NIC - Deployment
Make sure there is only one management NIC with IP address (setup is complaining about multiple gateways)


## Network Adapters
Same network adapters in one intent (speed and type)


## RDMA
RDMA off for Compute_Management Intent in the settings. Almost no switch can do RDMA!


## Custom Loation
Custom Loation only underscore, numbers and letters


## Bitlocker
Export yout Bitlocker keys!!!!
on one of the Nodes from the Cluster open a Powershell an execute
```PowerShell
Get-AsRecoveryKeyInfo | ft ComputerName, PasswordID, RecoveryKey
```
Example Output:
```PowerShell
 PS C:\Users\ashciuser> Get-AsRecoveryKeyInfo | ft ComputerName, PasswordID, RecoveryKey

 ComputerName    PasswordId    RecoveryKey
 -------         ----------    -----------
 ASB88RR1OU19    {Password1}   Key1
 ASB88RR1OU20    {Password2}   Key2
 ASB88RR1OU21    {Password3}   Key3
 ASB88RR1OU22    {Password4}   Key4
```

https://learn.microsoft.com/en-us/azure-stack/hci/manage/manage-bitlocker


## The created switch must be used for the Logical Network!
https://learn.microsoft.com/de-de/azure/aks/hybrid/aks-networks?tabs=azureportal


## Windows Admin Center
Why do i still need the Windows Admin Center in 23H2??
Some settings are still only available in the Windows Admin Center, for example:
- Nested Virtualization
- MAC address spoofing on the network adapter (e.g. for Nested Virtualization)
- Extensions for Hardware Management (e.g. Lenovo XCLarity)

## Classic administrative tools
- Hyper-V Manager
- Failover Cluster Manager
These tools are still very useful for managing the Azure Stack.

## Script Collection.
In this folder you will find a ZIP “AzureStackHCIScripts.zip” which contains the following scripts about:

- Clean Disks AZS.ps1 - Clean all non OS-Disks
- Resource-Based Delegation.ps1 - for 22H2
- SSO WAC.ps1 - Single Sign On for Windows Admin Center
- Windows Admin Center Cert 20 Years.ps1 - Create Certs for the Windows Admin Center with 20 years duration
