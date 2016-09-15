#this script configures iSCSI to run HCK tests

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

