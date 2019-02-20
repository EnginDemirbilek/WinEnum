<#
Powershell script to detect privilege escalate vectors in windows environments.
Author: Engin Demirbilek
Date: */*/*
Twitter: @hyal0id
Github Repository: https://github.com/EnginDemirbilek/WinEnum
#>

$Global:ServiceTable = $null
$Global:ScheduledTasksTable = $null
$Global:GeneralInfoTable = $null

 

function Check-Permissions($folder){
$user = $env:username
 $perm = (Get-Acl $folder -ErrorAction SilentlyContinue).Access |select IdentityReference, FileSystemRights | where-object {$_.IdentityReference -match "BUILTIN\\Users" -or $_.IdentityReference -match "everyone" -or $_.IdentityReference -match $user}
 return $perm
}



function Check-General{

Write-Host `n
$Global:GeneralInfoTable = New-Object System.Data.DataTable
$Global:GeneralInfoTable.Columns.Add("OS") |out-null
$Global:GeneralInfoTable.Columns.Add("Processors")|out-null
$Global:GeneralInfoTable.Columns.Add("Architecture")|out-null
$Global:GeneralInfoTable.Columns.Add("CurrentUser")|out-null
$Global:GeneralInfoTable.Columns.Add("ComputerName")|out-null
$Global:GeneralInfoTable.Columns.Add("MachineType")|out-null


Write-Host -BackgroundColor red "General Info"

$arc = $env:PROCESSOR_ARCHITECTURE
$fullos = (Get-WmiObject win32_operatingsystem).name
$rawos = $fullos.Split(" ")
$os = $rawos[1] + " " +$rawos[2]+ " "+$rawos[3]
$processor = (Get-WmiObject win32_processor).numberoflogicalprocessors
$user = $env:username
$computername= $env:COMPUTERNAME
$machine_type = Check-IsVirtual

$Global:GeneralInfoTable.Rows.Add($os,$processor,$arc,$user,$computername,$machine_type)

}

function Check-LocalAdmins{

Write-Host `n
Write-Host -ForegroundColor Green "[+] Local Admins "  

net localgroup "administrators" | where {$_ -notmatch "Alias" -and $_ -notmatch "Comment" -and $_ -notmatch "Member" -and $_ -notmatch "----" -and $_ -notmatch "The command"}

Write-Host `n


}

function Check-IsVirtual{
$machineType = ((get-wmiobject -computer LocalHost win32_computersystem).Manufacturer) | Where {$_ -Match "VM" -or $_ -Match "Virtual" -or $_ -Match "Hyper"}
       if(!$machineType)
        {
           
            $machinetype = "Physical Machine (Not a virtual one)"
            return $machineType 
        }
    else{
           
             $machinetype += " (Its a virtual machine)"
             return $machineType
        }
       

}

function Check-Domain{

Write-Host -BackgroundColor red "Domain Info"

if((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
Write-Host -NoNewline -ForegroundColor Green "[+] Domain= "
Write-Host -ForegroundColor Yellow (Get-WmiObject -Class Win32_ComputerSystem).Domain
Write-Host -NoNewline -ForegroundColor Green "[+] Domain Admins= "
net group /DOMAIN "domain admins" | where {$_ -AND $_ -notmatch "command completed successfully" -AND $_ -notmatch "---" -AND $_ -notmatch "Comment" -AND $_ -notmatch "Alias" -AND $_ -notmatch "Members" -AND $_ -notmatch "Group name" -AND $_ -notmatch "Domain admins" -AND $_ -notmatch "The request"}
Write-Host -NoNewline -ForegroundColor Green "[+] DC (via LOGONSERVER variable)= "
$env:LOGONSERVER

}
else{
Write-Host -ForegroundColor Yellow "Host is not a member of a domain"
}
Write-Host `n
}


function Check-SecurityUpdates{

Write-Host -BackgroundColor red "Security Updates"

Get-HotFix |select HotFixID,InstalledOn
Write-Host `n
}


function Check-AlwaysInstallElevated{

Write-Host -BackgroundColor red "Checking AlwaysInstallElevated Registery"
if((Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer") -and (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer")){
Write-Host -ForegroundColor Green "[+]! Host may be vulnerable to AlwaysInstallElevated Exploitation, checking registery keys for grant"

$hklm_key = (reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated)
$hklm_key = $hklm_key.Split(" ")
$hklm_key = $hklm_key | where {$_ -notmatch "HKEY" -AND $_ -notmatch "Always" -AND $_ -notmatch "REG_DWORD"}

$hkcu_key = (reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated)
$hkcu_key = $hkcu_key.Split(" ")
$hkcu_key = $hkcu_key | where {$_ -notmatch "HKEY" -AND $_ -notmatch "Always" -AND $_ -notmatch "REG_DWORD"}

if($hklm_key -eq "0x1" -and $hkcu_key -eq "0x1"){
Write-Host -NoNewline -ForegroundColor Yellow "[+][+][+] Vulnerability granted !!! "
Write-Host -ForegroundColor Green "Check: https://pentestlab.blog/2017/02/28/always-install-elevated/ for exploitation" 
    }
    else
    {
    Write-Host "Vulnerability couldn't granted but it seems vulnerable, check exploitation just in case: https:///"
    }



    
}
else{
Write-Host -ForegroundColor Yellow "[-] Host is not appear to vulnerable"
}
Write-Host `n
}



function Check-UnquotedServicePath{
Write-Host -BackgroundColor Red "Checking unquoted service paths"
$services = (Get-WmiObject win32_service |select state,name,pathname,startmode | where {$_.pathname -notmatch "\`"" -and $_.pathname -notmatch "C:\\WINDOWS" -and $_.pathname -match "\\"})
if($services){
Write-Host -ForegroundColor Green "[+][+]Vulnerable services found, check https://pentestlab.blog/2017/03/09/unquoted-service-path/ for possible exploitation"

$services

}
else
{
Write-Host -ForegroundColor Yellow "[-] 0 unquoted services path found."
}

Write `n
}




function Check-ServiceExecutablePermissions{

$Global:ServiceTable = New-Object System.Data.DataTable

$Global:ServiceTable.Columns.Add("ServiceName")| Out-Null
$Global:ServiceTable.Columns.Add("Executable")| Out-Null
$Global:ServiceTable.Columns.Add("ExecutablePermissions")| Out-Null


Write-Host -BackgroundColor Red "Checking permissions of service executables."
Write `n


(Get-WmiObject win32_service |select state,name,pathname,startmode | where {$_.pathname -notmatch "C:\\WINDOWS" -and $_.pathname -match "\\"}) | ForEach-Object{
 $name = $_.name 
 $path=$_.pathname
 $path = $path.Replace("`"","")
 $perms = Check-Permissions -folder $path
 $Global:ServiceTable.Rows.Add($name,$path,$perms)
 
}



}


function Check-GeneralPasswordFolders{
$isFound = 0
Write-Host `n
Write-Host -BackgroundColor Red "Checking Password Folders ..."
$windir =  $env:windir
$path_3 = $windir + "\Panther\Unattend\Unattended.xml"
$path_4 = $windir + "\Panther\Unattended.xml"
$paths = @("c:\sysprep.inf","c:\sysprep\sysprep.xml", $path_3,$path_4)
$paths
$paths | ForEach-Object{
if(Test-Path $_)
{
$isFound = 1
Write-Host -NoNewline -ForegroundColor Yellow "[+]Password folder seems exist, check: "
Write-Host -ForegroundColor Green $_
}



}

if(!$isfound)
{
Write-Host -ForegroundColor Yellow "No password folder found"
}


Write-Host `n
}


Function Check-ScheduledTaskExecutablePermissions
{
$Global:ScheduledTasksTable = New-Object System.Data.Datatable

$Global:ScheduledTasksTable.Columns.Add("TaskName") |Out-Null
$Global:ScheduledTasksTable.Columns.Add("ExecutionInterval") |Out-Null
$Global:ScheduledTasksTable.Columns.Add("Executable") |Out-Null
$Global:ScheduledTasksTable.Columns.Add("ExecutablePermissions") | Out-Null
$Global:ScheduledTasksTable.Columns.Add("Owner")| Out-Null

Get-ScheduledTask | Select * | Where {$_.TaskPath -notmatch "\\Microsoft\\Windows\\"  -AND $_.Principal.UserID -notmatch "$env:username"} |  ForEach-Object{

$name = $_.taskname
$owner =  $_.Principal.UserID
$interval =  (Get-ScheduledTask -Taskname $name).Triggers.Repetition.Interval
$executable = (Get-ScheduledTask -Taskname $name).Actions.Execute
$executable = $executable.Replace("`"","")
$executablePermissions = Check-Permissions $executable
$Global:ScheduledTasksTable.rows.add($name,$interval,$executable,$executablePermissions,$owner)


Write-Host `n
}
$Global:ScheduledTasksTable

}
