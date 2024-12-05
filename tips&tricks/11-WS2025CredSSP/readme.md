First you need to configure local machine to trust remote machines and remote machine to allow CredSSP connection

```PowerShell
    $ClusterName="AXClus02"
    $CredSSPServers=(Get-ClusterNode -Cluster $ClusterName).Name,$ClusterName

    #Configure CredSSP First
        #since just Enable-WSMANCredSSP no longer works in WS2025, let's configure it via registry
            $key = 'hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            if (!(Test-Path $key)) {
                New-Item $key
            }
        
            #New-ItemProperty -Path $key -Name AllowFreshCredentialsWhenNTLMOnly -Value 1 -PropertyType Dword -Force
            #New-ItemProperty -Path $key -Name AllowFreshCredentials -Value 1 -PropertyType Dword -Force
        
            $keys = 'hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly','hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
            foreach ($Key in $keys){
                if (!(Test-Path $key)) {
                    New-Item $key
                }
        
                $i=1
                foreach ($Server in $CredSSPServers){
                    New-ItemProperty -Path $key -Name $i -Value "WSMAN/$Server" -PropertyType String -Force
                    $i++
                }
            }

        #Enable CredSSP Server on remote machine
        Invoke-Command -ComputerName $CredSSPServers -ScriptBlock { Enable-WSManCredSSP Server -Force }

    #Disable CredSSP
    <#
        #Disable-WSManCredSSP -Role Client
        Remove-Item -Path 'hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Recurse
        Invoke-Command -ComputerName $CredSSPServers -ScriptBlock {Disable-WSManCredSSP Server}
    #>

```

You can now send commands to remote machines

```PowerShell

    $ClusterName="AXClus02"
    #Create Credentials
        $CredSSPUserName="Corp\LabAdmin"
        $CredSSPPassword="LS1setup!"
        $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)
        #or just 
        #Credentials=Get-Credential

    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        Write-Output "Hello World"
    }

```

Or you can remote in one of the nodes like this

```PowerShell
    $Server="AXNode3"

    $CredSSPUserName="Corp\LabAdmin"
    $CredSSPPassword="LS1setup!"
    $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)
    #or just 
    #Credentials=Get-Credential

    Enter-PSSession -ComputerName $Server -Credential $Credentials -Authentication Credssp
```
