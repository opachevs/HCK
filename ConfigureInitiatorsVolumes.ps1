# this script creates InitiatorsGroup and adds all the windows initiators to the group (2 fc initiators & 1 iSCSI initiator)
# this script creates volumes and maps them to the InitiatorsGroup.
# note: preparations run iSCSI.Config.ps1

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



Function ConfigureInitiatorsVolumes(){

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

write-host "Reseting iscsi service"
write-host "Stopping iscsi servece"
StopIscsiService
write-host "Starting iscsi service"
StartIscsiService

#Get initiator-groups to check if Win_iSCSI_IG already exists
$uri = $uri_prefix + "initiator-groups"
$OBJ=Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

#Adding InitiatorGroup Win_iSCSI_IG
write-host 'Adding InitiatorGroup Win_iSCSI_IG'
 $uri = $uri_prefix + "initiator-groups"
$pobj = [pscustomobject]@{}
$init_grp="Win_iSCSI_IG"
$flag=0
if($OBJ.'initiator-groups'.name.count -gt 1){
    for($i = 0 ; $i -le $OBJ.'initiator-groups'.name.count ; $i++){
        if($init_grp -eq $OBJ.'initiator-groups'.name[$i]){
            $flag=1
        }
    }
}else{
     if($init_grp -eq $OBJ.'initiator-groups'.name){
        $flag=1            
     }
}
#if flag==1 that means that Win_iSCSI_IG already exists
if($flag -eq 0){
    Add-Member -InputObject $pobj -type NoteProperty -name ig-name -value $init_grp
    $jobj = ConvertTo-Json $pobj
    $OBJ=Invoke-RestMethod -Uri $uri -Method Post -Body $jobj -Headers $headers -ContentType "application/json"
    if ($error) {Exit}
}
write-host "successful"

#Get initiator-groups to extract ig_id
$uri = $uri_prefix + "initiator-groups"
$OBJ=Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

#extracting ig_id
if($OBJ.'initiator-groups'.name.count -gt 1){
    for($i = 0 ; $i -le $OBJ.'initiator-groups'.name.count ; $i++){
        if($init_grp -eq $OBJ.'initiator-groups'.name[$i]){
            break
        }
    }
    $tmp=$OBJ.'initiator-groups'.href[$i]
    $tmp=$tmp.Split('/')
    $ig_id=$tmp[$tmp.Count -1]
    $ig_id=[convert]::ToInt32($ig_id,10)
}else{
    $tmp=$OBJ.'initiator-groups'.href
    $tmp=$tmp.Split('/')
    $ig_id=$tmp[$tmp.Count -1]
    $ig_id=[convert]::ToInt32($ig_id,10)
}

#Get initiator to check if Win_iSCSI_Initiator already exists
$uri = $uri_prefix + "initiators"
$OBJ=Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

#adding the initiators to the InitiatorGroup Win_iSCSI_IG
write-host 'Adding windows Initiator Win_iSCSI_Initiator to InitiatorGroup Win_iSCSI_IG'
$uri = $uri_prefix + "initiators"
$pobj = [pscustomobject]@{}
$init_name="Win_iSCSI_Initiator"
$InitiatorIqn=Get-InitiatorPort -Connectiontype iSCSI | Select-Object -Property NodeAddress
$InitiatorIqn=$InitiatorIqn.NodeAddress
$flag=0
if($OBJ.initiators.name.count -gt 1){
    for($i = 0 ; $i -le $OBJ.initiators.name.count ; $i++){
        if($init_name -eq $OBJ.initiators.name[$i]){
            $flag=1
        }
    }
}else{
    if($init_name -eq $OBJ.initiators.name){
            $flag=1
        }
}
#if flag==1 that means that Win_iSCSI_Initiator already exists
if($flag -eq 0){
    Add-Member -InputObject $pobj -type NoteProperty -name ig-id -value $ig_id
    Add-Member -InputObject $pobj -type NoteProperty -name initiator-name -value $init_name
    Add-Member -InputObject $pobj -type NoteProperty -name port-address -value $InitiatorIqn
    $jobj = ConvertTo-Json $pobj
    $OBJ=Invoke-RestMethod -Uri $uri -Method Post -Body $jobj -Headers $headers -ContentType "application/json"
    if ($error) {Exit}
}
write-host "successful"

#Get Volumes
$uri = $uri_prefix + "volumes"
$OBJ=Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

#adding volumes and mapping them to Win_iSCSI_IG 
write-host 'Adding volumes and mapping them to Win_iSCSI_IG'
for($j=0 ;$j -le $Vol_Num -1  ; $j++){
    $uri = $uri_prefix + "volumes"
    $pobj = [pscustomobject]@{}
    $vol_name="Win_iSCSI_Volume" + $Vol_Size + "_" + $j
    $flag=0
    if($OBJ.volumes.name.count -gt 1){
        for($i = 0 ; $i -le $OBJ.volumes.name.count ; $i++){
            if($vol_name -eq $OBJ.volumes.name[$i]){
                $flag=1
            }
        }

    }else{
         if($vol_name -eq $OBJ.volumes.name){
                $flag=1
        }
    }
   #if flag==1 that means that the volume already exists
    if($flag -eq 0){
        Add-Member -InputObject $pobj -type NoteProperty -name vol-size -value $vol_size
        Add-Member -InputObject $pobj -type NoteProperty -name vol-name -value $vol_name
        $jobj = ConvertTo-Json $pobj
        $OBJ=Invoke-RestMethod -Uri $uri -Method Post -Body $jobj -Headers $headers -ContentType "application/json"
        if ($error) {Exit}

        #Get Volumes to extract vol_id
        $uri = $uri_prefix + "volumes"
        $OBJ=Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

        #extracting vol_id
        if($OBJ.volumes.name.count -gt 1){
            for($i = 0 ; $i -le $OBJ.volumes.name.count ; $i++){
                if($vol_name -eq $OBJ.volumes.name[$i]){
                    break
                }
            }
            $tmp=$OBJ.volumes.href[$i]
            $tmp=$tmp.Split('/')
            $vol_id=$tmp[$tmp.Count -1]
            $vol_id=[convert]::ToInt32($vol_id,10)
        }else{
           $tmp=$OBJ.volumes.href
            $tmp=$tmp.Split('/')
            $vol_id=$tmp[$tmp.Count -1]
            $vol_id=[convert]::ToInt32($vol_id,10) 
        }
        #mapping the new volume
        $uri = $uri_prefix + "lun-maps"
        $pobj = [pscustomobject]@{}
        Add-Member -InputObject $pobj -type NoteProperty -name ig-id -value $ig_id
        Add-Member -InputObject $pobj -type NoteProperty -name vol-id -value $vol_id
        $jobj = ConvertTo-Json $pobj
        $OBJ=Invoke-RestMethod -Uri $uri -Method Post -Body $jobj -Headers $headers -ContentType "application/json"
        if ($error) {Exit}      
        
    }
}
write-host "successful"

}



if ($args.count -ne 4){
    Write-Output '.\ConfigureInitiatorsVolumes <drm/gy> <xbrick#> <NumOfVolumes[1-10]> <VolumeSize>'
    Write-Output 'example -> .\ConfigureInitiatorsVolumes drm 901 5 2T'
    exit 0
}

if ($args[0] -eq 'drm'){
    $uri_prefix = "https://vxms-xbrickdrm" + $args[1] + ".xiodrm.lab.emc.com/api/json/types/"
     
}Elseif ($args[0] -eq 'gy'){
    $uri_prefix = "https://vxms-xbrick" + $args[1] + ".xiolab.lab.emc.com/api/json/types/" 
   
}Else{
    Write-Output 'try again, let me remaind you.. <drm/gy>'
    Write-Output 'example -> .\ConfigureInitiatorsVolumes drm 901 5 2T'
}

Write-Output 'Starting .\ConfigureInitiatorsVolumes script'

$Vol_Num=$args[2]
$Vol_Size=$args[3]


# calculate the third ip octet
$tmp=$args[1] % 1000
if($tmp -gt 254){
    $tmp=$tmp % 100
}


ConfigureInitiatorsVolumes

