#this script configures iSCSI to run HCK tests


Function GetIscsiServiceStatus
{
    <#
    .SYNOPSIS
    Get iSCSI Service status
    Returns Running/Stopped string
    .DESCRIPTION
    Gets MicroSoft iSCSI Service current status from Host (Running/Stopped)
    .PARAMETER
    .OUTPUT System.String
    #>
    $Result = get-service "MSiSCSI" |select status | % {$_.status}
    return [string]$Result
}

Function StartIscsiService
{
    <#
    .SYNOPSIS
    Starting MSiSCSI service
    Returns True/False string
    .DESCRIPTION
    Starting MSiSCSI service and return True/False accordingly
    .PARAMETER
    returns: string
    #>
	try
	{
		Start-Service "MSiSCSI" -Erroraction stop
	}
	catch
	{
		$ErrorMessage = $_.Exception.Message
		if ($ErrorMessage)
		{
			write-host "Unable to start service MSiSCSI"
			Return "False"
		}
	}
	return "True"
}

Function StopIscsiService
{
    <#
     .SYNOPSIS
    Stopping MSiSCSI service
    Returns True/False string
    .DESCRIPTION
    Stopping MSiSCSI service and return True/False accordingly
    .PARAMETER
    returns: string
    #>
    try
	{
		Stop-Service "MSiSCSI" -Erroraction stop
	}
	catch
	{
		$ErrorMessage = $_.Exception.Message
		if ($ErrorMessage)
		{
			write-host "Unable to stop service MSiSCSI"
			Return "False"
		}
	}
	return "True"
}

Function GetIscsiIpAddress
{
    <#
     .SYNOPSIS
    Get enabled (!) Host's iSCSI IP addresses
    Returns iSCSI ports IP addresses
    .DESCRIPTION
    Get Host's iSCSI IP addresses according to Ethernet adapter type -> iSCSI ethertype = "ixgb", returns IP addresses
    .PARAMETER
    .OUTPUT System.String
    #>
    $etherType = "*ixgb*"
    $interface = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName .
    $script:IscsiIpAddress = foreach ($inter in $interface)
        {
            if (($inter | select ServiceName | % {$_.ServiceName}) -like $etherType)
            {
                $inter | select ipAddress | % {$_.ipAddress}
            }
        }
    return $IscsiIpAddress
}

Function GetManagementIpAddress
{
    <#
     .SYNOPSIS
    Get enabled(!) Host's management IP addresses
    Returns Management port IP address
    .DESCRIPTION
    Get Host's management IP addresses according to Ethernet adapter type --> "express", return IP addresses
    .PARAMETER
    .OUTPUT System.String
    #>
    $etherType = "*express*"
    $interface = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName .
    $script:ManagementIpAddress =foreach ($inter in $interface)
        {
            if (($inter | select ServiceName | % {$_.ServiceName}) -like $etherType)
            {
                $inter | select ipAddress | % {$_.ipAddress}
            }
        }
    return $ManagementIpAddress[0]
}

Function GetIpNetworkingInfo
{
<#
    .SYNOPSIS
    Get enabled(!) networking ports info
    Returns table with network ports info (e.g. IPAddress, IPSubnet, DefaultIPGateway, MACAddress)
    .DESCRIPTION
    Get Host's networking info (IP Address, Subnet, D.G., MAC Address, DHCP (true/false) for enabled ports
    .PARAMETER
    .OUTPUT System.String
    #>
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . |
    Select-Object [A-Z]* | select InterfaceIndex, IPAddress, IPSubnet, DefaultIPGateway, MACAddress, DHCPEnabled |
    format-table -AutoSize
}

Function GetHwNetworkingInfo
{
<#
    .SYNOPSIS
    Get enabled(!) networking ports Hardware info
    Returns table with network ports hardware info (e.g. NetConnectionID, Description, InterfaceIndex, Speed)
    .DESCRIPTION
    Get Host's networking ports Hardware info (NetworkConnectionID, NetConnectionStatus, Description, InterfaceIndex,
    MACAddress, Speed
    .PARAMETER
    .OUTPUT System.String
    #>
    Get-WmiObject -Class Win32_NetworkAdapter -Filter "NetConnectionStatus = 2" |Format-Table -Property NetConnectionID,
    Description, InterfaceIndex, MACAddress, Speed -AutoSize
}

Function GetNetworkPortStatusByName ([string]$PortName)
{
	<#
    .SYNOPSIS
    Get Networking port status by given Name
    Returns port status
    .DESCRIPTION
    Get Networking port status by given Name, statuses are numeric transformed to description string
    For example: GetNetworkPortStatusByName "iscsi2"
    .PARAMETER
    Param: PortName, Network port alias name
    Type: string
    .OUTPUT System.String
    #>
	$IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
		$Status = (Get-WmiObject win32_networkadapter | Select-Object [A-Z]* |
		where {$_.NetConnectionID -eq $PortName}).netconnectionstatus
		switch ($Status)
		{
			0 {"Port is Disabled"}
			1 {"Connecting"}
			2 {"Connected - Up"}
			3 {"Disconnecting"}
			4 {"Hardware not present"}
			5 {"Hardware disabled"}
			6 {"Hardware malfunction"}
			7 {"Media disconnected - Network Cable Unplugged"}
			default {"Status of Port is not clear, please check Port Name and LG"}
		}
    }
	else
	{
		foreach ($i in (Get-NetAdapter))
		{
			if ($i.Name -eq $PortName)
			{
				Return ([string]$i.Status)
			}
		}
    }
}

Function SetNetworkPortState
{
    <#
    .SYNOPSIS
    Set networking port state
    Returns True/False
    .DESCRIPTION
    Set networking port state, function should get Network port name and desired state (as 'disable'/'enable' only)
    For example: SetPortState -PortName "iSCSI2" -State enable
    .PARAMETER
    Param: PortName, Network port alias name
    Type: string
    Param: State, desired state Disable/Enable
    Type: string
    .OUTPUT System.Boolean
    #>
    param (
        [String]$PortName,
        [ValidateSet('Disable', 'Enable')]
        [String]$State
    )
	$IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
        $Adapter = (Get-WmiObject win32_NetworkAdapter | where {$_.NetConnectionID -eq $PortName})
		if ($state -eq "Disable")
		{
        $adapter.Disable()
        return $?
		}
		$adapter.Enable()
        return $?
	}
    else
    {
        if ($state -eq "Disable")
		{
			Disable-NetAdapter -Name $PortName -Confirm:$false
			return $?
		}
		Enable-NetAdapter -Name $PortName -Confirm:$false
		return $?
	}
}

Function SetNetworkPortIpAddress ([string]$PortName, [string]$Address, [string]$Gateway = "")
{
<#
    .SYNOPSIS
    Sets IP Address to specified interface by port name
    Returns True/False string
    .DESCRIPTION
    Sets IP Address to specified interface by port name, mandatory args: Address where Address
    includes IP Address and Prefix, optional arg: Default Gateway
    For example: SetIpAddress "iSCSI1" 1.2.3.4/24 "1.2.3.254"
                 SetIpAddress "iSCSI2" 10.10.10.10/16
    .PARAMETER
    Param: PortName, Network port alias name
    Type: string
    Param: Address, New IP address to assign including Sunbet Prefix (i.e. 10.10.10.10/16)
    Type: string
    Param: Gateway New Default Gateway address to assign (optional)
    Type: string
    .OUTPUT System.String
    #>
    $IPAddress = ($Address.Split("/"))[0]
    $Subnet = ($Address.Split("/"))[1]
    $IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
        $index = (Get-WmiObject win32_NetworkAdapter | where {$_.NetConnectionID -eq $PortName}).InterfaceIndex
        $NetInterface = Get-WmiObject Win32_NetworkAdapterConfiguration | where {$_.InterfaceIndex -eq $index}
        $NetInterface.enabledhcp()
        $Adapter = (Get-WmiObject win32_NetworkAdapter | where {$_.NetConnectionID -eq $PortName})
        $Adapter.disable()
        $Adapter.enable()
        $SubnetMask = GetMask $subnet
        $NetInterface.EnableStatic($IPAddress, [string]$SubnetMask)
        $Adapter.disable()
        $Adapter.enable()
        if ($gateway)
            {
                $NetInterface.SetGateways($gateway)
            }
        Return "True"
    }
    else
    {
        $NetAdapter = Get-NetAdapter -Name $PortName
        $NetAdapter | Remove-NetIPAddress -Confirm:$false
        $NetAdapter | Set-NetIPInterface -DHCP Disabled
        if (Get-NetIPConfiguration -InterfaceAlias $PortName | select IPv4DefaultGateway | % {$_.IPv4DefaultGateway})
        {
            Remove-NetRoute -InterfaceAlias $PortName -DestinationPrefix 0.0.0.0/0 -confirm:$false
        }
        if ($gateway)
        {
            $NetAdapter | New-NetIPAddress -IPAddress $IPAddress -PrefixLength $Subnet -DefaultGateway $Gateway
        }
        else
        {
            $NetAdapter | New-NetIPAddress -IPAddress $IPAddress -PrefixLength $Subnet
        }
        Return "True"
    }
    Return "False"
}

Function SetDhcpAddress ([string]$PortName)
{
<#
    .SYNOPSIS
    Set IP Address to specific Port by DHCP Server
    Returns True/False string
    .DESCRIPTION
    Set IP Address to specific Port by DHCP Server
    For example: SetDhcpAddress "iSCSI2"
    .PARAMETER
    Param: PortName, Network port alias name
    Type: String
    .OUTPUT System.String
    #>
    $IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
        $index = (Get-WmiObject win32_NetworkAdapter | where {$_.NetConnectionID -eq $PortName}).InterfaceIndex
        $NetInterface = Get-WmiObject Win32_NetworkAdapterConfiguration | where {$_.InterfaceIndex -eq $index}
        $NetInterface.enabledhcp()
        $Adapter = (Get-WmiObject win32_NetworkAdapter | where {$_.NetConnectionID -eq $PortName})
        $Adapter.disable()
        $Adapter.enable()
        Return "True"
    }
    else
    {
    $NetAdapter = Get-NetAdapter -Name $PortName
    $NetAdapter | Set-NetIPInterface -DHCP Enabled
    Return "True"
    }
    Return "False"
}

Function RenameNetworkAdapter ([string]$CurrentName, [string]$NewName)
{
<#
    .SYNOPSIS
    Rename Network adapter name
    Returns True/False
    .DESCRIPTION
    Rename Network adapter name, function gets 2 mandatory arguments: "CurrentName", "NewName"
    For example: RenameNetworkPort "iSCSI1" "iSCSI20"
    .PARAMETER
    Param: CurrentName, current Network port alias name
    Type: string
    Param: NewName, new Network port alias name
    Type: string
    .OUTPUT System.Boolean
    #>
    $IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
        $Adapter = Get-WmiObject win32_NetworkAdapter | where {$_.NetConnectionID -eq $CurrentName}
        $Adapter.NetConnectionID = $NewName
        $Adapter.Put()
        $?
    }
    else
    {
    Rename-NetAdapter -Name $CurrentName -NewName $NewName
    $?
    }
}


Function GetIscsiPortsName
{
	<#
    .SYNOPSIS
    Get current names for iSCSI ports on Client
	Returns List of iSCSI ports names
	.DESCRIPTION
    Get current names for iSCSI ports on Client (the names can be used for other functions)
	.PARAMETER
    .OUTPUT System.Array
    #>
	$IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
	{
		$PortName = ((Get-WmiObject win32_NetworkAdapter | where {$_.servicename -eq "ixgbn"}).netconnectionid)
		return $PortName
	}
	else
	{
		$ports = Get-NetAdapter
		foreach ($i in $ports)
        {
            if ($i.linkspeed -eq "10 Gbps")
            {
				$i.name
			}
        }
	}
}

Function DiscoverPortal ([string]$portal, [int]$port = 3260)
{
    <#
    .SYNOPSIS
    Initiate iSCSI Discovery to a given <portal_ip>
	Returns True/False string
	.DESCRIPTION
    Initiate Discovery to a given <portal_ip> with default TCP port=3260, user can change Port to non-default TCP port.
	Pay attention - The result of discovered Portals depends on Single Discovery feature supported by Cluster version.
    Examples:   DiscoverPortal 10.61.3.5 - will make discover to portal 10.61.3.5:3260
                DiscoverPortal 10.61.3.5 222 - will make discover to portal  10.61.3.5:222
	.PARAMETER
    Param: Portal, IP address to make Discovery to
    Type: string
	Param: Port, iSCSI TCP port
    Type: string
    .OUTPUT System.String
    #>
    if ( -Not $Portal)
    {
	write-host "Portal Address is missing!!!"
	return "False"
	}
	Write-Host "Trying to make Discovery to portal:" $portal":"$port
    $IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
		$Result = iscsicli AddTargetPortal $Portal $Port
		foreach ($line in $Result)
		{
			if ($line.Contains("completed successfully"))
			{
				Return "True"
			}
		}
		Write-Host "Failed to make Discovery to portal:" $portal":"$port
		iscsicli RemoveTargetPortal $portal $port
		iscsicli RefreshTargetPortal $portal $port
		return "False"
	}
	else
	{
		$error.clear()
		New-IscsiTargetPortal -TargetPortalAddress $portal -TargetPortalPortNumber $port
        if ($error)
        {
			Write-Host "Failed to make Discovery to portal:" $portal":"$port
		    Remove-IscsiTargetPortal -TargetPortalAddress $portal -Confirm:$false
		    Update-IscsiTarget
		    Return "False"
		}
    }
	Return "True"
}

Function GetIscsiTargetDiscovered
{
    <#
    .SYNOPSIS
    Get list of all Targets exposed to Client (by Discovery)
	Returns List of Targets' IQN discovered
	.DESCRIPTION
    Get list of all Targets exposed to Client (by Discovery)
	.PARAMETER
    .OUTPUT System.Array
    #>
	$IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
		$Result = iscsicli ListTargets
		foreach ($i in $Result.trim()) {if ($i.Contains("iqn")){$i}}
	}
	else
	{
		Get-IscsiTarget | select NodeAddress | % {$_.NodeAddress}
	}
}

Function LoginByTargetName ($Target = "all")
{
    <#
	.SYNOPSIS
    Executing iSCSI Login to given Target name or all found Targets names (by Discovery)
	Returns True/False string
	.DESCRIPTION
    Executing iSCSI Login to given Target name or all found Targets names (by Discovery)
    Examples:   LoginByTargetName - will make Login to all found targets
                LoginByTargetName iqn.2008-05.com.xtremio:001e6780cb40 - will make Login to specified target
	.PARAMETER
    Param: Target, Specific Target to make Login to, optional
    Type: string
    .OUTPUT System.String
    #>
	$IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
		if ($Target -eq "all")
		{
			$Result = iscsicli ListTargets
			$Targets = foreach ($i in $Result.trim())
			{
				if ($i.Contains("iqn"))
				{
				$i
				}
			}
			if ($Targets)
			{
				foreach ($CLS_tar in $Targets)
				{
					$Result = iscsicli QLoginTarget $CLS_tar
					foreach ($line in $Result)
					{
						if ($line.Contains("target name is not found"))
						{
							Write-Host "Could not Login to some or all Targets"
							Return "False"
						}
						if ($line.Contains("target has already been logged in"))
						{
							Write-Host "The target" $cls_tar "has already been logged in"
						}
					}
				}
			}
			else
			{
				Write-Host "No Targets found"
				Return "False"
			}
        }
		else
		{
			$Result = iscsicli QLoginTarget $Target
			foreach ($line in $Result)
			{
				if ($line.Contains("target name is not found"))
				{
					Write-Host "Could not Login to some or all Targets"
					Return "False"
				}
			}
            if ($line.Contains("target has already been logged in"))
            {
				Write-Host "The target" $target "has already been logged in"
			}
		}
	Return "True"
	}
	else
	{
        $error.clear()
		if ($Target -eq "all")
        {
            $Targets = Get-IscsiTarget |select NodeAddress | % {$_.NodeAddress}
            if ($Targets)
            {
                $targets
                foreach ($CLS_tar in $targets)
                {
                    try
                    {
						Connect-IscsiTarget -NodeAddress $CLS_tar -Erroraction stop
					}
                    catch
                    {
                        $ErrorMessage = $_.Exception.Message
                        if ($ErrorMessage.Contains("The target has already been logged in via an iSCSI session."))
                        {
							Write-Host "The target" $cls_tar "has already been logged in"
							$error.clear()
                        }
                        else
                        {
							Return "False"
						}
                    }
                }
            }
            else
            {
            Write-Host "No Targets found"
            }
        }
        else
        {
            try
            {
				Connect-IscsiTarget -NodeAddress $Target -Erroraction stop
			}
            catch
            {
                $ErrorMessage = $_.Exception.Message
                if ($ErrorMessage.Contains("The target has already been logged in via an iSCSI session."))
                {
                    Write-Host "The target" $target "has already been logged in"
                    $error.clear()
                }
                else
                {
					Return "False"
				}
            }
        }
		if ($error)
		{
			Write-Host "Could not Login to some or all Targets"
			Return "False"
		}
		else
		{
			Return "True"
		}
    }
}

Function GetIscsiTargetLoggedIn
{
    <#
    .SYNOPSIS
    Get list of all Targets Client had Logged-in to
	Returns List of Targets' IQN Logged-in
	.DESCRIPTION
    Get list of all Targets Client had Logged-in to (by Login)
	.PARAMETER
    .OUTPUT System.Array
    #>
	$IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
		$login = iscsicli.exe ReportTargetMappings
		foreach ($i in $login)
		{
			if ($i.Contains("Target Name"))
			{
				(($i -replace " ","").split(":")[1]+":"+($i -replace " ","").split(":")[2])
			}
		}
	}
	else
	{
		$Target = Get-IscsiTarget
		foreach ($Tar in $Target)
		{
			if (($Tar | select IsConnected | % {$_.IsConnected}) -eq "True")
			{
				$Tar | select NodeAddress | % {$_.NodeAddress}
			}
		}
	}
}

Function GetLoggedInTargetPortalConnection
{
    <#
    .SYNOPSIS
    Get Logged in targets names and associated Portal in Hash table
	Returns Hash table with Targets and associated Portals for Logged in Targets
	.DESCRIPTION
    Get Logged in targets names and associated Portal in Hash table
	.PARAMETER
    .OUTPUT System.Hash
    #>
	$i = 0
	$TargetId = (iscsicli SessionList | Select-String "Target Name", "Target Portal") -replace " ",""
	$TargetIdNew = do
	{
		if (($i)%3 -ne 0)
		{
			$TargetId[$i]
		}
		$i++
	}
	While ($i -le $TargetId.count)
	$TargetSessionId = foreach ($i in $TargetIdNew)
	{
		if ($i)
		{
			if ($i.Contains("TargetPortal:"))
			{
				$i -replace "TargetPortal:",""
			}
			if ($i.Contains("TargetName:"))
			{
				$i -replace "TargetName:",""
			}
		}
	}
	$hash = $null
	$hash = @{}
	$count = ($TargetSessionId.count)
	for($idx=0; $idx -lt $count; $idx+=2)
	{
		$hash.add($TargetSessionId[($idx+1)],$TargetSessionId[($idx)])
	}
	Return $hash
}

Function LogoutByTargetName ($Target = "all")
{
    <#
	.SYNOPSIS
    Executing iSCSI Logout from given Target name or all found Targets names (which are Logged in)
	Returns True/False string
	.DESCRIPTION
    Executing iSCSI Logout from given Target name or all found Targets names (which are Logged in)
	Function will return True if specific Target given was Logged in and got logged out or in case of Logging out with
	option all - atleast one target was found to logged out from (if no Target was found function will return False)
    Examples:   LogoutByTargetName - will make Logout from all found targets
                LogoutByTargetName iqn.2008-05.com.xtremio:001e6780cb40 - will make Logout from specified target
	.PARAMETER
    Param: Target, Specific Target to make Login to, optional
    Type: string
    .OUTPUT System.String
    #>
	$IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
		$loggedIn = iscsicli.exe ReportTargetMappings
		$LoggedTargets = foreach ($i in $loggedIn)
		{
			if ($i.Contains("Target Name"))
			{
				(($i -replace " ","").split(":")[1]+":"+($i -replace " ","").split(":")[2])
			}
		}
		if (-Not $LoggedTargets)
		{
			Write-Host "No Target found to logout from"
			return "False"
		}
		else
		{
			$idx = 0
			$TargetIdFull = (iscsicli SessionList | Select-String "Session id", "Target Name") -replace " ",""
			$TargetId = do
			{
				if (($idx+1)%3 -ne 0)
				{
					$TargetIdFull[$idx]
				}
				$idx++
			}
			While ($idx -le $TargetIdFull.count)
			$TargetIdNew = foreach ($i in $TargetId)
			{
				if ($i)
				{
					if ($i.Contains("SessionId:"))
					{
						$i -replace "SessionId:",""
					}
					if ($i.Contains("TargetName:"))
					{
						$i -replace "TargetName:",""
					}
				}
			}
			$hash = $null
			$hash = @{}
			$count = ($TargetIdNew.count)
			for($idx=0; $idx -lt $count; $idx+=2)
			{
				$hash.add($TargetIdNew[($idx+1)],$TargetIdNew[($idx)])
			}
			if ($Target -eq "all")
			{
				foreach ($Target in $LoggedTargets)
				{
					$TargetLine = $hash.GetEnumerator() | Where-Object {$_.key -eq $Target}
					$SessionId = $TargetLine.value
					iscsicli logouttarget $SessionId
				}
				return "True"
			}
			else
			{
				$TargetLine = $hash.GetEnumerator() | Where-Object {$_.key -eq $Target}
				if ($TargetLine)
				{
					$SessionId = $TargetLine.value
					iscsicli logouttarget $SessionId
					return "True"
				}
				else
				{
					write-Host "Given Target not found or not logged in"
					return "False"
				}
			}
		}
	}
	else
	{
		$TargetList = Get-IscsiTarget
		$LoggedTargets = foreach ($Tar in $TargetList)
		{
			if (($Tar | select IsConnected | % {$_.IsConnected}) -eq "True")
			{
				$Tar | select NodeAddress | % {$_.NodeAddress}
			}
		}
		if (-Not $LoggedTargets)
		{
			Write-Host "No Target found to logout from"
			return "False"
		}
		else
		{
			if ($target -eq "all")
			{
				Disconnect-IscsiTarget -Confirm:$false
				return "True"
			}
			else
			{
				if ($LoggedTargets.Contains($Target))
				{
					Disconnect-IscsiTarget -NodeAddress $Target -Confirm:$false
					return "True"
				}
				else
				{
					write-Host "Given Target not found or not logged in"
					return "False"
				}
			}
		}
	}
}

Function RemoveTargetPortal ([string]$portal, [int]$port = 3260)
{
    <#
    .SYNOPSIS
    Initiate iSCSI "Un-discover" to a given <portal_ip>
	Returns True/False string
	.DESCRIPTION
    Initiate "Un-discover" to a given <portal_ip> with default TCP port=3260, user can change Port to non-default TCP port.
    Examples:   RemoveTargetPortal 10.61.3.5 - will make discover to portal 10.61.3.5:3260
                RemoveTargetPortal 10.61.3.5 222 - will make discover to portal  10.61.3.5:222
	Notice(1) Making un-discover when Target is connected - the Portal will be deleted from Discovery table but connection will still
			  exist - Use LogoutByTargetName function to Logout from connection
	Notice(2) - Currently for Win2012 no way to use TCP port argument for this function!!!
	.PARAMETER
    Param: Portal, IP address to make un-discover from
    Type: string
	Param: Port, iSCSI TCP port
    Type: string
    .OUTPUT System.String
    #>
    if ( -Not $Portal)
    {
	write-host "Portal Address is missing!!!"
	return "False"
	}
	Write-Host "Trying to make Un-discover from portal:" $portal":"$port
    $IsWin2008 = IsWin2k08
    if ($IsWin2008 -eq "True")
    {
		$Result = iscsicli RemoveTargetPortal $portal $port
		iscsicli RefreshTargetPortal $portal $port
		foreach ($line in $Result)
		{
			if ($line.Contains("completed successfully"))
			{
				Return "True"
			}
		}
			Write-Host "The specified portal was not found."
			return "False"
	}
	else
	{
		$error.clear()
		try
        {
			Remove-IscsiTargetPortal -TargetPortalAddress $portal -Confirm:$false -Erroraction stop
		}
        catch
        {
            $ErrorMessage = $_.Exception.Message
		}
		if ($ErrorMessage)
		{
			$ErrorMessage
			return "False"
		}
		else
		{
			Update-IscsiTarget
			Return "True"
		}
	}
}


Function IsWin2k08
{
    <#
    .SYNOPSIS
    Auxiliary function to determine if Windows client is Win2008 or Win2012
    Returns True/False string
    .DESCRIPTION
    Auxiliary function to determine if Windows client is Win2008 or Win2012, used for functions where the commands
    don't have same commands syntax
    .PARAMETER
    .OUTPUT System.String
    #>
    $result = if (([System.Environment]::OSVersion.Version | select Minor | % {$_.Minor}) -eq 1){"True"} else{"False"}
    return $Result
}

Function GetMaskAddress ([int]$Prefix)
{
	<#
    .SYNOPSIS
    Converts subnet address from prefix mode to full address (limited from 1..32)
    Returns Subnet Mask address
    .DESCRIPTION
    Converts subnet address from prefix mode to full address, i.e. 'GetMask 16' returns '255.255.0.0'
    .PARAMETER
    Param: Prefix, Prefix number represents the Subnet Mask address
    Type: integer
    .OUTPUT System.String
    #>
    if (($prefix -lt 1) -or ($prefix -gt 32))
    {
    return "False - Number too big for sunbet convention"
    }
    $temp = 1
    $bin = ""
    while ($temp -le $Prefix)
    {
        $bin = $bin + "1"
        $temp ++
    }
    $q = ((("1" * ($Prefix)).PadRight(32, "0")).Insert(8,'.').Insert(17,'.').Insert(26,'.')).split(".")
    $dex=$i=$null
    $q |
    % {
     $i++
     [string]$dex += [convert]::ToInt32($_,2)
     if($i -le 3) {[string]$dex += "."}
   }
   return $dex
}


<#

.SYNOPSIS

Rescans disks, , Brings disks online, Initiates the disks, Partitions disks for maximum size and formats disks as NTFS


.DESCRIPTION

Rescans disks, Initiates them and partitions them for maximum size and formats them as NTFS


.PARAMETER

None


.EXAMPLE

RescanAndPartitionDisks


.NOTES

Works only in Windows 2012 and above

#>
Function MakeDisksReady()
{

    Try
    {        
        $CurrentDisks = Get-Disk
        $MaxCurrentDisks = ($CurrentDisks | Measure-Object -Property Number -Maximum).Maximum
        $LocalDisks = 0   
        For ($i = 1 ; $i -le $MaxCurrentDisks; $i++) 
        {   
            $XtremIOCounter = $i - $LocalDisks             
            If(Get-Disk ?Number $i | Where-Object PartitionStyle ?Eq "RAW")
            { 
                Initialize-Disk -Number $i -PassThru | Out-Null                    
                $XtremIO = "XtremIO$XtremIOCounter" 
                New-Partition ?DiskNumber $i ?UseMaximumSize | Out-Null
                Add-PartitionAccessPath -DiskNumber $i -PartitionNumber 2 -AssignDriveLetter | Out-Null
                Get-Partition ?Disknumber $i ?PartitionNumber 2 | Format-Volume ?FileSystem NTFS ?NewFileSystemLabel $XtremIO ?Confirm:$false | Out-Null           
            }
            else
            {
                $LocalDisks++            
            }
        
        }
        $ReadyDisks = $MaxCurrentDisks - $LocalDisks  
        Write-Host $ReadyDisks 'Disks Are Ready Now!' -foregroundcolor green
        $LastDrive = Get-Partition
        $LastDrive = $LastDrive[-1].DriveLetter
        return $LastDrive
    }    
    Catch
    {
        [system.exception]
        "Error Making Disks Ready!"
    }    
}



<#

.SYNOPSIS

Installs Windows' MultiPath (MPIO) Feature, or EMC's PowerPath ontop of Windows' MultiPath


.DESCRIPTION

Installs Windows' MultiPath (MPIO) Feature, or EMC's PowerPath ontop of Windows' MultiPath (If MPIO is not installed, it will install it, and then install PowerPath)


.PARAMETER

MPIO (MultiPath) or PP (PowerPath)


.EXAMPLE

LgPath MPIO
LgPath PP


.NOTES

LgPath function reboots machine on success for finalizing installation, User needs to relogin to machine (This will be automated as well soon) 
Supported in Windows 2008R2 and above

#>
Function LgPath($Path)
{
    Try
    {       
        # Check if Microsoft's MultiPath (MPIO) Feature is enabled, if it is enabled and function was called to Enable MPIO, return True, otherwise enable MultiPath
        Write-Output "Check if Microsoft's MultiPath (MPIO) Feature is Enabled"
        if(isMpioInstalled)
        {
            Write-Output "Microsoft's MultiPath (MPIO) Feature is already Enabled"
            if($Path -eq 'MPIO')
            {              
                return $True;
            }
            # If function was called to install PowerPath, check if PowerPath is already installed, if yes return true, otherwise install PowerPath 
            elseif($Path -eq 'PP')
            {                
                Try
                {
                    #Check if EMC's PowerPath is installed                    
                    if(IsPowerPathInstalled)
                    {
                        Write-Output "EMC's PowerPath is already installed"                        
                        return $True
                    }
                    elseif(-NOT (IsPowerPathInstalled))
                    {
                        #EMC's PowerPath is not installed, installing it...
                        Write-Output "EMC's PowerPath is NOT installed, installing it..."                        
                        InstallPowerPath                        
                        return $True
                    }
                }
                Catch
                {
                    [system.exception]
                    "Error installing EMC's PowerPath!"
                }
                return $True;
            }
        }
        # Microsoft's MultiPath (MPIO) Feature is NOT enabled. If function was called to enable MultiPath, enable MultiPath, and if function was called to install PowerPath
        # First enable MultiPath, and then install PowerPath
        elseif(-NOT (isMpioInstalled))
        {
            Write-Output "Microsoft's MultiPath (MPIO) Feature is NOT Enabled, Enabling it..."
            Try
            {
                InstallMpio
                SetXtremioDsmHw
            }
            Catch
            {
                [system.exception]
                "Error Enabling Microsoft's MultiPath Feature!"
            }    
            if($Path -eq 'MPIO')
            {                
                Write-Output "Microsoft's MultiPath (MPIO) Feature is enabled"
                return $True;
            }                            
            elseif($Path -eq 'PP')
            {
                Write-Output "Microsoft's MultiPath (MPIO) Feature is enabled,installing EMC's PowerPath"
                Try
                {
                    InstallPowerPath
                }
                Catch
                {
                    [system.exception]
                    "Error installing EMC's PowerPath!"
                }
                return $True;
            }
         }
         else
         {
            Write-Output "Invalid option, Only MPIO and PP are currently allowed as parameters to LgPath function (MPIO and PP refer to Microsoft''s MPIO and EMC's PowerPath respectively)"
            return $True;
         }                                          
    }
    Catch
    {
        [system.exception]
        "Error Configuring LGPath"
    }    
}



Function iSCSI_Config{

# checks if iSCSI service runnig 
if ($(GetIscsiServiceStatus) -eq 'Stopped')
    {
        Write-Output 'iSCSI service stopped. Starting iSCSI service'
        StartIscsiService
    }

    LogoutByTargetName

#Set iSCSI Service Startup Mode to Automatic
    Set-Service -Name MsiSCSI -StartupType Automatic

    $IscsiPortsNames = GetIscsiPortsName

    #Renaming Network Adapters
    Write-Output 'Renaming Network Adapters as iSCSI1 and iSCSI2'
    RenameNetworkAdapter $IscsiPortsNames[0] 'iSCSI1'
    RenameNetworkAdapter $IscsiPortsNames[1] 'iSCSI2'

    #Connects iSCSI Ports
    Write-Output 'Connect iSCSI Ports' 
    $IscsiPortsNames = GetIscsiPortsName    
    foreach ($Port in $IscsiPortsNames)
    {
        $PortStatus = GetNetworkPortStatusByName $Port
        if ($PortStatus -ne 'Up')
        { 
            SetNetworkPortState -PortName $Port -state enable
            sleep 3
            $PortStatus = GetNetworkPortStatusByName $Port   
        }
    }

    #Gets Management I.P Address (We need the last two octecs) 
    Write-Output 'Get Management I.P'
    $MngIpAddr = GetManagementIpAddress
    if ($MngIpAddr.Count -gt 1)
    {
        $MngIpAddr = $MngIpAddr[-1]
    }
    $TempIP = $MngIpAddr.split('.')
    $TempIP[0] = 10
    $TempIP[1] = 205
    $NewIscsi1IP = $TempIP -join'.'
    $TempIP[1] = 206
    $NewIscsi2IP = $TempIP -join'.'

    #Sets iSCSI1 and iSCSI2 network adapters' I.Ps
    Write-Output 'Setting iSCSI1 and iSCSI2 network adapters'' I.Ps'
    SetNetworkPortIpAddress 'iSCSI1' $NewIscsi1IP/16
    SetNetworkPortIpAddress 'iSCSI2' $NewIscsi2IP/16

    #Shows Network Adapters Information
    Write-Output 'Network Adapters Info:'
    GetIpNetworkingInfo

    #iSCSI Service needs to restart due to a bug in Microsoft's code after changing NIC name: http://www.c-amie.co.uk/technical/2012-new-IscsiTargetPortal-connection-failed/
    Write-Output 'Restarting iSCSI service after changing Network Adapters (NICs) names'
    Restart-Service msiscsi

    $error.clear()
#SSL certificate for working with Power Shell
if (-not ("IDontCarePolicy" -as [type])) {
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;

    public class IDontCarePolicy : ICertificatePolicy {
        public IDontCarePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@}
[System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy

#Cluster's credentials
$user="tech"
$pass="X10Tech!"
$EncAuth=[System.Text.Encoding]::UTF8.GetBytes($user+':'+$pass)
$EncPass=[System.Convert]::ToBase64String($EncAuth)
$headers=@{"Authorization"="Basic $($EncPass)"}


#Adding iSCSI-portals to Cluster
Write-Output 'Adding iSCSI portals'
$uri = $uri_prefix + "iscsi-portals"
$OBJ=Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
$portals=$OBJ.'iscsi-portals'.name

$tar_arr=(3,4,7,8)
$uri = $uri_prefix + "iscsi-portals"
for($i = 0 ; $i -le 3; $i++){
    $error.clear()
    $pobj = [pscustomobject]@{}
    $tar_id=$tar_arr[$i]
    $ip_addr="10.205." + $tmp + "." + $tar_id + "/16"
    $flag=0
    # checks if the portal exists
    if($portals.count -ne 0){
        for($j = 0 ; $j -le $portals.count ; $j++){
            if($ip_addr -eq $portals[$j]){
                $flag=1
            }
        }
    }
    if($flag -eq 0){
        Add-Member -InputObject $pobj -type NoteProperty -name tar-id -value $tar_id
        Add-Member -InputObject $pobj -type NoteProperty -name ip-addr -value $ip_addr
        $jobj = ConvertTo-Json $pobj
        $OBJ=Invoke-RestMethod -Uri $uri -Method Post -Body $jobj -Headers $headers -ContentType "application/json"
    }
}
    $ip_addr="10.205." + $tmp + ".3"

    sleep 3
    #Discover Portals
    Write-Output 'Discovering all portals with portal ' $ip_addr
    $tmp=0
    $err=DiscoverPortal $ip_addr
    while($err -eq "False"){
        Write-Output 'DiscoverPortal Failed, Retrying...'
        StopIscsiService
        StartIscsiService
        $tmp++
        if($tmp -eq 5){
            Write-Output 'Failed 5 times to DiscoverPortal...'
            exit 1
        }
        sleep 3
        $err=DiscoverPortal $ip_addr
    } 

    #Get iSCSI Targets Discovered
    Write-Output ' Targets Discovered:'
    GetIscsiTargetDiscovered

    #Login to all Targets
    Write-Output 'Logging-in to All Targets'
    LoginByTargetName

    #Get iSCSI Logged-in Targets
    Write-Output 'Logged-in Targets:'
    GetIscsiTargetLoggedIn

     #Get Logged-in Targets Names and Associated Portals
    Write-Output 'Logged-in Targets Names and Associated Portals:'
    GetLoggedInTargetPortalConnection

  
}

if ($args.count -ne 2){
    Write-Output '.\iSCSI_Config <drm/gy> <xbrick#>'
     Write-Output 'example -> .\iSCSI_Config drm 901'
    exit 0
}
if ($args[0] -eq 'drm'){
    $uri_prefix = "https://vxms-xbrickdrm" + $args[1] + ".xiodrm.lab.emc.com/api/json/types/"
     
}Elseif ($args[0] -eq 'gy'){
    $uri_prefix = "https://vxms-xbrick" + $args[1] + ".xiolab.lab.emc.com/api/json/types/" 
   
}Else{
    Write-Output 'try again, let me remaind you.. <drm/gy>'
    Write-Output 'example -> .\iSCSI_Config drm 901'
}
Write-Output 'Starting .\iSCSI_Config script'

# calculate the third ip octet
$tmp=$args[1] % 1000
if($tmp -gt 254){
    $tmp=$tmp % 100
}

iSCSI_Config

