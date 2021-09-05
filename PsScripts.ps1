Function nc() {
    <#
    .SYNOPSIS
    Check active connections

    .DESCRIPTION
    This PS script for checking all active network connections.

    .PARAMETER resolve
    Tries to resolve ip address by sending a json query to ip-api.com

    .PARAMETER out
    Sending output to Out-GridView

    .PARAMETER getprocess
    Getting the processname for all active connections

    .PARAMETER fullreport
    Runs all parameters

    .EXAMPLE
    netconn [-out] [-resolve] [-getprocess] [-all]

    .NOTES
    Author : Trond Weiseth
    #>

    param(
        [CmdletBinding()]
        [switch]$Resolve,
        [switch]$Out,
        [switch]$GetProcess,
        [switch]$Fullreport,

        [Parameter(Mandatory = $false, ParameterSetName = "Status")]
        [ValidateSet('listen', 'established', 'bound', 'timeWait', 'closeWait')]
        [string]$Status
    )

    $nic = Get-NetAdapter | where { $_.Status -eq "Up" } | select -ExpandProperty Name
    $localip = Get-NetIPAddress -InterfaceAlias $nic -AddressFamily IPv4 | select -ExpandProperty IPAddress

    Function connquery() {
        if ($Status) {
            Get-NetTCPConnection -LocalAddress $localip -state $Status
        }
        else {
            Get-NetTCPConnection -LocalAddress $localip
        }
    }
    function fetchprocess() {
        $pids = connquery | Select-Object -ExpandProperty OwningProcess
        $pids | ForEach-Object { Get-Process -Id $_ | Select-Object Id, ProcessName } | Format-Table
    }
    function getconnections() {
        if ($Out) {
            connquery | Out-GridView
        }
        else {
            connquery
        }
    }
    function resolver() {
        if ($Status) {
            $iplist = Get-NetTCPConnection -LocalAddress $localip -state $Status | select -ExpandProperty RemoteAddress
        }
        else {
            $iplist = Get-NetTCPConnection -LocalAddress $localip | select -ExpandProperty RemoteAddress
        }
        if ($Out) {
            $iplist | ForEach-Object { Invoke-RestMethod -Uri http://ip-api.com/json/$_ } | Out-GridView
        }
        else {
            $iplist | ForEach-Object { Invoke-RestMethod -Uri http://ip-api.com/json/$_ | Select-Object query, country, countryCode, region, regionName, city, zip, timezone, isp, org, as } | Format-Table -Autosize -Wrap
            
        }
    }

    if ($Fullreport) {
        getconnections
        fetchprocess
        resolver
    }
    else {
        if ($Getprocess) {
            fetchprocess
        }
        else {
            if ($Resolve) {
                resolver
            }
            else {
                getconnections
            }
        }
    }
}

Function Resolve-IpAddress() {
    param(
        [Parameter(Mandatory = $true, Position = 1)][string]$ipadr
    )
    Invoke-RestMethod -Uri http://ip-api.com/json/$ipadr | Select-Object query, country, countryCode, region, regionName, city, zip, timezone, isp, org, as | Format-Table -Autosize -Wrap
}

Function Get-TcpProcess() {
    param(
        [Parameter(ValueFromPipeline = $true)][string]$pipelineinput
    )
    process {
        $pipelineinput | ForEach-Object { Get-Process -Id $_ | select Name, Id }
    }
}

Function RemoteConnections() {
    $process = @{
        Name = 'ProcessName'
        Expression = { (Get-Process -Id $_.OwningProcess).Name }
    }
    
    $darkAgent = @{
        Name = 'ExternalIdentity'
        Expression = { 
        $ip = $_.RemoteAddress 
        (Invoke-RestMethod -Uri "http://ipinfo.io/$ip/json" -UseBasicParsing -ErrorAction Ignore).org
      
        }
    }
    Get-NetTCPConnection -RemotePort 443 -State Established |
        Select-Object -Property RemoteAddress, OwningProcess, $process, $darkAgent | Format-Table -AutoSize
}

Function Hash() {

    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$File,
        [Parameter(Mandatory = $true, Position = 1)][string]$Compare,
        [Parameter()]
        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')]
        [string]$Algorithm
    )

    if (!$Algorithm) { $Algorithm = 'MD5' }

    $FileHash = Get-FileHash -Path $File -Algorithm $Algorithm | Select -ExpandProperty Hash

    if ($Compare -eq $FileHash) { Write-Host -ForegroundColor Yellow "$Algorithm hash match." }
    else { Write-Host -ForegroundColor Red "$Algorithm hash do not match!" }
}

Function pp() {
    notepad++.exe $profile
}

Function ss() {
    & $PROFILE
}

Function newfunction() {
    param(
        [Parameter(Mandatory = $false, Position = 0)][string]$FunctionName,
        [Parameter(Mandatory = $false, Position = 1)][string]$FunctionAction
    )
	
    function functhelp() {
        echo "Usage: newfuntion [FunctionNAme] ['executed funtion']"
    }

    if (!$FunctionName -or !$FunctionAction) { functhelp }
    else {
        "`nFunction $FunctionName() {
		$FunctionAction
}" >> C:\Users\tweiseth\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
    }
}

Function whatsmyip() {
    curl ifconfig.me
}

Function Service {

    param(
        [CmdletBinding()]
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true)][string]$comm,
        [switch]$start,
        [switch]$stop,
        [switch]$restart,
        [switch]$dependencies,
        [switch]$bringup,
        [switch]$bringdown,
        [Parameter(Mandatory = $false, ParameterSetName = "Startup")]
        [ValidateSet("Automatic", "Boot", "Disabled", "Manual", "System")]
        [string]$startup
    )
	
    $res = Get-Service -displayname *$comm* -ErrorAction SilentlyContinue | select status, name, displayname, StartType
    if ($res -ne $null) {
        $m = $res | select -ExpandProperty name | measure | select -ExpandProperty Count
        if ($m -gt 1) {
            $servsel = $res | out-gridview -PassThru
            $servname = $servsel | select -ExpandProperty Name
        }
        else {
            $servname = $res | select -ExpandProperty Name
        }
        
    }
    else {
        $res = Get-Service -name *$comm* | select status, name, displayname, StartType
        $m = $res | select -ExpandProperty name | measure | select -ExpandProperty Count
        if ($m -gt 1) {
            $servsel = $res | out-gridview -PassThru
            $servname = $servsel | select -ExpandProperty Name
        }
        else {
            $servname = $res | select -ExpandProperty Name
        }
    }

    function main() {
        Get-Service $servname | select status, name, displayname, StartType | ft -AutoSize -Wrap
    }
	
    if ($dependencies) {
        #(get-service $servname).DependentServices | ft -AutoSize -Wrap
        (get-service $servname).RequiredServices | select Status, Name, DisplayName, StartType | ft -AutoSize -Wrap
    }
	
    elseif ($bringup) {
        Set-Service $servname -StartupType Manual
        (get-service $servname).RequiredServices | select Status, Name, StartType | where { $_.StartType -eq "Disabled" } | foreach { Set-Service $_.Name -StartupType Manual }
        Start-Service $servname
    }
	
    elseif ($bringdown) {
        (get-service $servname).RequiredServices | select Status, Name, StartType | where { $_.StartType -ne "Disabled" } | foreach { Set-Service $_.Name -StartupType Disabled }
        stop-Service $servname
        Set-Service $servname -StartupType Disabled
    }

    elseif ($start) {
        Start-Service $servname
        main
    }
  
    elseif ($stop) {
        stop-Service $servname
        main
    }
		
    elseif ($startup) {
        Set-Service $servname -StartupType $startup
        Get-Service $servname
    }
	
    else {
        main
    }
}

Function pingsweep() {
    param(
        [Parameter(Mandatory = $True, Position = 0)][string]$rhost
    )
    $iprange = $null
    1..254 | foreach { $iprange += , "$rhost.$_" }
    $iprange | ForEach-Object -Parallel { Test-Connection -Count 1 -IPv4 $_ | select -ExpandProperty Address | select -ExpandProperty IPAddressToString } -ThrottleLimit 10
}

Function log () {


    <# .SYNOPSIS

     EventLog parser 

.DESCRIPTION

     Gettng event logs on remote PC
     Example : 
              log -ComputerName contoso.local -newest 1000 -time 10:10 -logname system -date 14/10
              log contoso.local -after 10:00 -before 11:00 -date 14/10/2020 -o

.NOTES

     Author     : Trond Weiseth
#>

    param(
        [CmdletBinding()]
        [Parameter(Mandatory = $false, Position = 0)][string]$ComputerName,
        [string]$time,
        [string]$newest,
        [string]$before,
        [string]$after,
        [string]$date,
        [switch]$o,
        [switch]$help,
        [switch]$local,
        [Parameter(Mandatory = $false, ParameterSetName = "LogName")]
        [ValidateSet("system", "application", "security")]
        [string]$logname
    )
    
    if ($date -imatch 'day' -or $date -imatch 'today' -or $date -imatch 'current' -or $date -imatch 'now') {
        $date = $(get-date -Format MM/dd)
    }
          
    $uname = ("$env:USERDOMAIN\$env:USERNAME")
    $arglst = @("$newest", "$time", "$logname", "$date", "$before", "$after")

    function help() {

        Write-Host -ForegroundColor Green "###################################################################################################################################"
        Write-Host -ForegroundColor Yellow " Usage:"
        Write-Host -ForegroundColor Yellow "	log [[host] | [-local]] [-newest number] [-time time] [-logname system|application|security] [-date MM/dd/yyyy] [-before time] [-after time]"
        Write-Host "" 
        Write-Host -ForegroundColor Yellow " Options:"
        Write-Host -ForegroundColor Yellow "	-local		Runs the script on the local computer"
        Write-Host -ForegroundColor Yellow "	-newest		Sets the number of logs to be fetched from newest to old (Default 400)"
        Write-Host -ForegroundColor Yellow "	-time		Time when the log was created"
        Write-Host -ForegroundColor Yellow "	-logname	Name of logs to fetch. If not set, all logs will be fetched. [system|application|security]"
        Write-Host -ForegroundColor Yellow "	-date		Date when the log was created"
        Write-Host -ForegroundColor Yellow "	-before		Fetching logs before a given time"
        Write-Host -ForegroundColor Yellow "	-after		Fetching logs after a given time"
        Write-Host ""
        Write-Host -ForegroundColor Yellow " Example:"
        Write-Host ""    
        Write-Host -ForegroundColor Yellow "     log -local -newest 1000 -time 10:10 -logname system -date 10/14/2020"
        Write-Host -ForegroundColor Yellow "     log $env:COMPUTERNAME -logname system -before 11:00 -after 10:00 -date current"
        Write-Host -ForegroundColor Green "###################################################################################################################################"
    } 

    function parser1() {

        param (
            $newest,
            $time,
            $logname,
            $date,
            $before,
            $after
        )
    
        if (!$newest) { $newest = "200" }
        if ($after -and $before) {
            Get-EventLog -Newest $newest -LogName $logname | where { $_.TimeGenerated -gt $after -and $_.TimeGenerated -lt $before }
        }
        elseif ($after) {
            Get-EventLog -Newest $newest -LogName $logname | where { $_.TimeGenerated -gt $after }
        }
        elseif ($before) {
            Get-EventLog -Newest $newest -LogName $logname | where { $_.TimeGenerated -lt $before }
        }
        elseif ($date) {
            Get-EventLog -Newest $newest -LogName $logname | where { $_.TimeGenerated -imatch $date }
        }
        elseif ($date -and $before) {
            Get-EventLog -Newest $newest -LogName $logname | where { $_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before }
        }
        elseif ($date -and $before -and $after) {
            Get-EventLog -Newest $newest -LogName $logname | where { $_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before -and $_.TimeGenerated -gt $after }
        }
        else {
            Get-EventLog -Newest $newest -LogName $logname | where { $_.TimeGenerated -imatch "$time" }
        }
    }
 
    function parser2() {

        param (
            $newest,
            $time,
            $logname,
            $date,
            $before,
            $after
        )
    
        if (!$newest) { $newest = "200" }
        $lognames = "Application", "Security", "System"
    
        if ($after -and $before) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where { $_.TimeGenerated -gt $after -and $_.TimeGenerated -lt $before }
            }
        }
        elseif ($after) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where { $_.TimeGenerated -gt $after }
            }
        }
        elseif ($before) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where { $_.TimeGenerated -lt $before }
            }
        }
        elseif ($date) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where { $_.TimeGenerated -imatch $date }
            }
        }
        elseif ($date -and $before) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where { $_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before }
            }
        }
        elseif ($date -and $before -and $after) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where { $_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before -and $_.TimeGenerated -gt $after }
            }
        }
        else {
            $lognames | ForEach-Object {
                Get-EventLog -LogName $_ -Newest $newest | where { $_.TimeGenerated -imatch "$time" }
            }
        }
    }

    function outpars() {

        if ($o) {
            $res | Format-Table -AutoSize -Wrap
            $res | Format-Table -AutoSize -Wrap | clip
        }
        else {
            $res | Out-GridView -PassThru |  Format-Table -AutoSize -Wrap | clip
        }
    }


    if ($local) {
        if ($logname) {
            $res = Invoke-Command -ArgumentList ${arglst} -ScriptBlock ${function:parser1}
        }
        else {
            $res = Invoke-Command -ArgumentList ${arglst} -ScriptBlock ${function:parser2}
        }
        outpars
    }
    else {   
        if ($help -or !$ComputerName) {
            help
        }
        else {
            $cred = Get-Credential $uname 
            if ($logname) {
                $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList ${arglst} -ScriptBlock ${function:parser1}
            }
            else {
                $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList ${arglst} -ScriptBlock ${function:parser2}
            }
        }
        outpars
    }
}

Function Get-LastBootTime() {
    $uptime = ((get-date) - (gcim Win32_OperatingSystem).LastBootUpTime | select -ExpandProperty TotalMinutes)
    (get-date).AddMinutes(-$uptime)
}

Function Get-Uptime() {
    (get-date) - (gcim Win32_OperatingSystem).LastBootUpTime | select Days, Hours, Minutes, Seconds
}

Function Net-Test {

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false)][string]$rhost,
        [string]$remote,
        [int]$port,
        [int]$timeout,
        [switch]$help
    )

    function help() {
        write-host "SYNTAX: Net-Test [[-rhost] <string>] [-port <string>] [-remote <string>] [-timeout <string>] [-help]  [<CommonParameters>]" -ForegroundColor Yellow
    }

    if ( $help -or ! $rhost ) { help ; break }

    $IPMATCH = $rhost -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and [ipaddress]$rhost

    if ( ! $timeout ) { $timeout = 100 }

    if ($dnsres = Resolve-DnsName $rhost -DnsOnly -ErrorAction SilentlyContinue) {
        if ($dnsres | Select-Object -ExpandProperty NameHost -First 1 -ErrorAction SilentlyContinue) {
            $ComputerName = $dnsres | Select-Object -ExpandProperty NameHost -First 1
        }
        else {
            $ComputerName = $dnsres | Select-Object -ExpandProperty Name -First 1
        }
        $ipAddresses = $dnsres | Select-Object -ExpandProperty IP4Address -ErrorAction SilentlyContinue
        $RA = $dnsres | Select-Object -ExpandProperty IP4Address -ErrorAction SilentlyContinue -First 2
    }
    else {
        Write-Warning "Could not resolve DNS name`n"
        if ( $IPMATCH -eq $false ) { break }
        $ComputerName = $rhost
    }

    if ($IPMATCH -eq $true) {
        $RA = $rhost
        $ipAddresses = $rhost
    }

    $NicInformation = Find-NetRoute -RemoteIPAddress $RA
    $srcip = $NicInformation | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue
    $netinterface = $NicInformation | Select-Object -ExpandProperty InterfaceAlias -ErrorAction SilentlyContinue -First 1

    if ((Test-Connection localhost -Count 1 | Get-Member | ForEach-Object { $_.Name }) -imatch "Latency") { $pingproperty = "Latency" } else { $pingproperty = "ResponseTime" }

    if ($responsetime = Test-Connection $rhost -Count 1 -ErrorAction SilentlyContinue  | Select-Object -ExpandProperty $pingproperty) {
        $ping = "True"
    }
    else {
        $ping = "False"
    }

    function icmpoutput {
        param (
            $ComputerName,
            $RA,
            $netinterface,
            $srcip,
            $ping,
            $responsetime
        )
        Write-Host -ForegroundColor Cyan "===================================="
        Write-Host -NoNewline -ForegroundColor Green "CumputerName           : "; Write-Host -ForegroundColor Yellow "$ComputerName"
        Write-Host -NoNewline -ForegroundColor Green "RemoteAddress          : "; Write-Host -ForegroundColor Yellow "$RA"
        Write-Host -NoNewline -ForegroundColor Green "InterfaceAlias         : "; Write-Host -ForegroundColor Yellow "$netinterface"
        Write-Host -NoNewline -ForegroundColor Green "SourceAddress          : "; Write-Host -ForegroundColor Yellow "$srcip"
        Write-Host -NoNewline -ForegroundColor Green "PingSucceeded          : "; Write-Host -ForegroundColor Yellow "$ping"
        Write-Host -NoNewline -ForegroundColor Green "PingReplyDetails (RTT) : "; Write-Host -ForegroundColor Yellow "$responsetime ms"
        Write-Host -ForegroundColor Cyan "===================================="
    }

    function tcpoutput () {
        param (
            $ComputerName,
            $Remadr,
            $port,
            $netinterface,
            $srcip,
            $ping,
            $responsetime,
            $res
        )
        Write-Host -ForegroundColor Cyan "===================================="
        Write-Host -NoNewline -ForegroundColor Green "CumputerName           : "; Write-Host -ForegroundColor Yellow "$ComputerName"
        Write-Host -NoNewline -ForegroundColor Green "RemoteAddress          : "; Write-Host -ForegroundColor Yellow "$Remadr"
        Write-Host -NoNewline -ForegroundColor Green "RemotePort             : "; Write-Host -ForegroundColor Yellow "$port"
        Write-Host -NoNewline -ForegroundColor Green "InterfaceAlias         : "; Write-Host -ForegroundColor Yellow "$netinterface"
        Write-Host -NoNewline -ForegroundColor Green "SourceAddress          : "; Write-Host -ForegroundColor Yellow "$srcip"
        Write-Host -NoNewline -ForegroundColor Green "PingSucceeded          : "; Write-Host -ForegroundColor Yellow "$ping"
        Write-Host -NoNewline -ForegroundColor Green "PingReplyDetails (RTT) : "; Write-Host -ForegroundColor Yellow "$responsetime ms"
        Write-Host -NoNewline -ForegroundColor Green "TcpTestSucceeded       : "; Write-Host -ForegroundColor Yellow "$res"
        Write-Host -ForegroundColor Cyan "===================================="
    }

    function portTestBlock() {
        param(
            $ip,
            $port,
            $timeout
        )
        $tcpobject = new-Object system.Net.Sockets.TcpClient 
        #Connect to remote machine's port               
        $connect = $tcpobject.BeginConnect($ip, $port, $null, $null) 
        #Configure a timeout before quitting - time in milliseconds 
        $wait = $connect.AsyncWaitHandle.WaitOne($timeout, $false) 
        If (-Not $Wait) {
            Write-Warning "TCP connect to ($ip : $port) failed"
            $Global:res = "False"
            $Global:Remadr = $ip
        }
        Else {
            $error.clear()
            $tcpobject.EndConnect($connect) | out-Null
            $Global:res = "True"
            $Global:Remadr = $ip
        }
    }
    
    if ($remote) {
        if ($port) {
            foreach ($ip in $ipAddresses) { Invoke-Command -ArgumentList $ip, $port, $timeout -ScriptBlock ${function:portTestBlock} }
            Invoke-Command -ComputerName $remote -Credential $cred -ArgumentList $ComputerName, $Remadr, $port, $netinterface, $srcip, $ping, $responsetime, $res -ScriptBlock ${function:tcpoutput}
        }
        else {
            Invoke-Command -ArgumentList  $ComputerName, $RA, $netinterface, $srcip, $ping, $responsetime -ScriptBlock ${function:icmpoutput}
        }
    }
    else {
        if ($port) {
            foreach ($ip in $ipAddresses) { Invoke-Command -ArgumentList $ip, $port, $timeout -ScriptBlock ${function:portTestBlock} }
            Invoke-Command -ArgumentList $ComputerName, $Remadr, $port, $netinterface, $srcip, $ping, $responsetime, $res -ScriptBlock ${function:tcpoutput}
        }
        else {
            Invoke-Command -ArgumentList  $ComputerName, $RA, $netinterface, $srcip, $ping, $responsetime -ScriptBlock ${function:icmpoutput}
        }
    }
}

Function Test-Port {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, HelpMessage = 'Could be suffixed by :Port')]
        [String[]]$ComputerName,

        [Parameter(HelpMessage = 'Will be ignored if the port is given in the param ComputerName')]
        [Int]$Port = 5985,

        [Parameter(HelpMessage = 'Timeout in millisecond. Increase the value if you want to test Internet resources.')]
        [Int]$Timeout = 100
    )

    begin {
        $result = [System.Collections.ArrayList]::new()
    }

    process {
        foreach ($originalComputerName in $ComputerName) {
            $remoteInfo = $originalComputerName.Split(":")
            if ($remoteInfo.count -eq 1) {
                # In case $ComputerName in the form of 'host'
                $remoteHostname = $originalComputerName
                $remotePort = $Port
            }
            elseif ($remoteInfo.count -eq 2) {
                # In case $ComputerName in the form of 'host:port',
                # we often get host and port to check in this form.
                $remoteHostname = $remoteInfo[0]
                $remotePort = $remoteInfo[1]
            }
            else {
                $msg = "Got unknown format for the parameter ComputerName: " `
                    + "[$originalComputerName]. " `
                    + "The allowed formats is [hostname] or [hostname:port]."
                Write-Error $msg
                return
            }

            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $portOpened = $tcpClient.ConnectAsync($remoteHostname, $remotePort).Wait($Timeout)

            $null = $result.Add([PSCustomObject]@{
                    RemoteHostname       = $remoteHostname
                    RemotePort           = $remotePort
                    PortOpened           = $portOpened
                    TimeoutInMillisecond = $Timeout
                    SourceHostname       = $env:COMPUTERNAME
                    OriginalComputerName = $originalComputerName
                })
        }
    }

    end {
        return $result
    }
}

Function Uninstall-CleanUp() {
    param( 
        [Parameter(Position = 0, Mandatory = $false)][string]$softwarename,
        [switch]$RegistryBackup,
        [switch]$TestData
    )

    $registrypaths = @(
        "HKEY_CURRENT_USER\SOFTWARE\"
        "HKEY_CURRENT_USER\SOFTWARE\Classes\"
        "HKEY_LOCAL_MACHINE\SOFTWARE\"
        "HKEY_USERS\.DEFAULT\Software\"
        "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\"
    )

    $folderpaths = @(
        "C:\Program Files\"
        "C:\Program Files (x86)\"
        "E:\Program Files\"
        "E:\Program Files (x86)\"
        "$HOME\AppData\Roaming\"
        "$HOME\AppData\Local\"
    )

    $date = get-date -Format dd.MM.yyyy
    $registrykeys = [System.Collections.ArrayList]@()
    $folderlist = [System.Collections.ArrayList]@()

    function testdata() {
        $registrypaths | ForEach-Object { [void](New-Item -Path registry::$_ -Name "UninstallCleanupTest") }
        $folderpaths | ForEach-Object { [void](New-Item -Path $_ -ItemType Directory -Name "UninstallCleanupTest") }
        Write-Host -ForegroundColor Yellow "UninstallCleanupTest registry key and folders have been generated in all paths."
        Write-Host -ForegroundColor Yellow "To test the script, use: Uninstall-CleanUp UninstallCleanupTest"
        break
    }
	
    if ($TestData) { testdata }
	
    foreach ($registrypath in $registrypaths) {
        if ($registrykey = Get-ChildItem registry::$registrypath | Where-Object { $_.Name -imatch "$softwarename" } | Select-Object -ExpandProperty Name) {
            foreach ($regstring in $registrykey) {
                $arrayID = $registrykeys.Add($regstring)
            }
        }
    }

    if ($registrykeys) {
        $regselection = $registrykeys | Out-GridView -PassThru -Title "Registry Key(s)"
        if ($regselection) {
            if ($RegistryBackup) {
                if (!(Test-Path "C:\RegistryBackup_$date")) {
                    [void](New-Item -Path C:\ -ItemType Directory -Name "RegistryBackup_$date")
                }
                $backupfolder = "C:\RegistryBackup_$date"
                $regselection | ForEach-Object {
                    $regbackup = $_.Replace('\', '_')
                    [void](reg export $_ $backupfolder\$regbackup.reg /y)
                    if (Test-Path $backupfolder\$regbackup.reg) {
                        Write-Host -NoNewline -ForegroundColor Green "Backup of registry key: " ; write-host -ForegroundColor Cyan "$backupfolder\$regbackup.reg"
                    }
                }
            }
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "Selected registry key(s):"
            $regselection | ForEach-Object { write-host -ForegroundColor Cyan $_ }
            Write-Host -ForegroundColor Red -BackgroundColor Black -NoNewline "Remove registry key? (Y\N):"
            $answer = Read-Host
            if ($answer -eq "y") {
                $regselection | ForEach-Object {
                    Remove-Item Registry::$_ -Recurse
                    if (!(Test-Path $_)) {
                        Write-Host -NoNewline -ForegroundColor Red "Registry key removed : "; write-host -ForegroundColor Cyan $_
                    }
                    else { Write-Host -ForegroundColor Red "ERROR: Registry key did not get removed." }
                }
            }
        }
        else { Write-Host -ForegroundColor Red "No registry key(s) selected." }
    }

    foreach ($folderpath in $folderpaths) {
        if ($softwarepath = Get-ChildItem -Path $folderpath | Where-Object { $_.Name -imatch "$softwarename" } | Select-Object -ExpandProperty FullName) {
            foreach ($folder in $softwarepath) {
                $arrayID = $folderlist.Add($folder)
            }
        }
    }

    if ($folderlist) {
        $folderselection = $folderlist | Out-GridView -PassThru -Title "Folder(s)"
        if ($folderselection) {
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "Selected folder(s): "
            $folderselection | ForEach-Object { write-host -ForegroundColor Cyan $_ }
            Write-Host -ForegroundColor Red -BackgroundColor Black -NoNewline "Remove folder(s)? (Y\N):"
            $answer = Read-Host
            if ($answer -eq "y") {
                $folderselection | ForEach-Object {
                    Remove-Item $_ -Force
                    if (!(Test-Path $_)) {
                        Write-Host -NoNewline -ForegroundColor Red "Folder removed: " ; write-host -ForegroundColor Cyan $_
                    }
                    else { Write-Host -ForegroundColor Red "ERROR: Folder did not get removed." }
                }
            }
        }
        else { Write-Host -ForegroundColor Red "No folder(s) selected." }
    }
}

Function WeatherReport(){
	param([string]$Location,[switch]$Full,[switch]$Day,[switch]$Moon)
	if (!$Location) {$Location = "baerum"}
	if ($Full) {(Invoke-WebRequest "https://wttr.in/${Location}?F" -UserAgent "curl" ).Content}
	if ($Day) {(Invoke-WebRequest "https://wttr.in/${Location}?1F" -UserAgent "curl" ).Content}
	if ($Moon) {(Invoke-WebRequest "https://wttr.in/Moon?F" -UserAgent "curl" ).Content}
	if (!$Full -and !$Day -and !$Moon) {(Invoke-WebRequest "https://wttr.in/${Location}?0F" -UserAgent "curl" ).Content}
}

Function Clear-TempFolder() {
    Remove-Item $env:temp\* -Force -Recurse -ErrorAction SilentlyContinue
}

Function Get-Tsk {
    
# Getting/staring task from task scheduler on remote computer
# Example: Get-Tsk dc01.contoso.test -start
   
    param(
    [CmdletBinding()]
    [string[]]$ComputerName,
    [Parameter(Mandatory = $true)][string]$TaskName,
    [switch]$start,
    [switch]$stop,
    [switch]$Info,
    [switch]$Help
    )

    function help() {Write-Host -ForegroundColor Yellow "Syntax: Get-Task [-ComputerName] <host1,host2> [-TaskName] <string> [-start] [-stop] [-Info]`n"}
    if ($Help) {help}

    if ($ComputerName -imatch "sgf") {
        $uname=("sgf\bf-$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }
    function ComputerNameMsg(){
        Write-Host "`n           " -BackgroundColor DarkCyan -NoNewline
        write-host "ComputerName: $CN" -ForegroundColor Yellow -BackgroundColor DarkCyan -NoNewline
        Write-Host "           `n" -BackgroundColor DarkCyan
    }
    if (!$ComputerName) {
        if ($start) {Get-ScheduledTask *$TaskName* | Start-ScheduledTask}
            elseif ($stop) {Get-ScheduledTask *$TaskName* | Stop-ScheduledTask}
            elseif ($Info) {
                $tasknames = Get-ScheduledTask *$TaskName* | select TaskPath,TaskName -ErrorAction SilentlyContinue
                foreach ($tsk in $tasknames){Get-ScheduledTaskInfo -TaskPath $tsk.taskpath -TaskName $tsk.taskname -ErrorAction SilentlyContinue | select TaskName,LastRunTime,NextRunTime}
            }
            else {
                Get-ScheduledTask *$TaskName* | select TaskName,Date,Description | ft -AutoSize -wrap | Tee-Object -Variable res
                if($res -eq $null){Write-Warning "No match found!"}
            }
    }
    else {
        foreach ($CN in $ComputerName) {
            if ($start) {Invoke-Command -ComputerName $CN -Credential $cred -ArgumentList $TaskName -ScriptBlock {param($TaskName)Get-ScheduledTask $TaskName | Start-ScheduledTask}}
            elseif ($stop) {Invoke-Command -ComputerName $CN -Credential $cred -ArgumentList $TaskName -ScriptBlock {param($TaskName)Get-ScheduledTask $TaskName | Stop-ScheduledTask}}
            elseif ($Info) {
                Invoke-Command -ComputerName $CN -Credential $cred -ArgumentList $TaskName -ScriptBlock {param($TaskName)
                $tasknames = Get-ScheduledTask *$TaskName* | select TaskPath,TaskName -ErrorAction SilentlyContinue
                foreach ($tsk in $tasknames){Get-ScheduledTaskInfo -TaskPath $tsk.taskpath -TaskName $tsk.taskname -ErrorAction SilentlyContinue | select TaskName,LastRunTime,NextRunTime}
                }
            }
            else {
                ComputerNameMsg
                Invoke-Command -ComputerName $CN -Credential $cred -ArgumentList $TaskName -ScriptBlock {param($TaskName)Get-ScheduledTask *$TaskName* | select TaskName,Date,Description | ft -AutoSize -wrap} | Tee-Object -Variable res
                if($res -eq $null){Write-Warning "No match found!"}
            }
        }
    }
}

Function CimInstance($CimClassName) {

    $CimClasses = Get-CimClass *$CimClassName* | Select-Object -ExpandProperty CimClassName |  Out-GridView -PassThru

    Foreach ($CimClass in $CimClasses){
        Get-CimInstance $CimClass
    }
}
