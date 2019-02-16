<#
Powershell script to detect privilege escalate vectors in windows environments.
Author: Engin Demirbilek
Date: */*/*
Twitter: @hyal0id
Github Repository: 
#>

 

function Check-Permissions($folder){

 (Get-Acl $folder).Access |select IdentityReference, FileSystemRights | where-object {$_.IdentityReference -match "BUILTIN\\Users" -or $_.IdentityReference -match "everyone"} -erroraction 'silentlycontinue'

}



function Check-General{
Write-Host `n
Write-Host -BackgroundColor red "General Info"

$fullos = (Get-WmiObject win32_operatingsystem).name
$rawos = $fullos.Split(" ")
Write-Host -NoNewline -ForegroundColor Green "[+] Operating System= "
Write-Host -ForegroundColor Yellow $rawos[1] $rawos[2] $rawos[3]

$processor = (Get-WmiObject win32_processor).numberoflogicalprocessors
Write-Host -NoNewline -ForegroundColor Green "[+] Number Of Processors= "
Write-Host -ForegroundColor Yellow $processor
$user = $env:username
Write-Host -NoNewline -ForegroundColor Green "[+] Current User= "
Write-Host -ForegroundColor Yellow  $user
Write-Host -NoNewline -ForegroundColor Green "[+] Computer Name= "
Write-Host -ForegroundColor Yellow  $env:COMPUTERNAME
 
Write-Host -ForegroundColor Green "[+] IP Addresses of Machine " 
((Get-WmiObject Win32_NetworkAdapterConfiguration).IpAddress) | Where-Object {$_ -notmatch ":"}

Write-Host `n
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
            Write-Host -NoNewline -ForegroundColor Green "[+] Machine Type= "
            Write-Host -ForegroundColor Yellow  "Physical (Not a virtual machine)"
        }
    else{
            Write-Host -NoNewline -ForegroundColor Green "[+] Machine Type= "
            Write-Host -ForegroundColor Yellow -NoNewline  "Virtual: " $machineType 
        }
        Write-Host `n

}

function Check-Domain{

Write-Host -BackgroundColor red "Domain Info"

if((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain){
Write-Host -NoNewline -ForegroundColor Green "[+] Domain= "
Write-Host -ForegroundColor Yellow (Get-WmiObject -Class Win32_ComputerSystem).Domain
Write-Host -NoNewline -ForegroundColor Green "[+] Domain Admins= "
net group /DOMAIN "domain admins" | where {$_ -AND $_ -notmatch "command completed successfully" -AND $_ -notmatch "---" -AND $_ -notmatch "Comment" -AND $_ -notmatch "Alias" -AND $_ -notmatch "Members" -AND $_ -notmatch "Group name" -AND $_ -notmatch "Domain admins"}
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

Write-Host -BackgroundColor Red "Checking permissions of service executables."
Write `n
$services = (Get-WmiObject win32_service |select state,name,pathname,startmode | where {$_.pathname -notmatch "C:\\WINDOWS" -and $_.pathname -match "\\"})
$i = 0
if($services){
    while($services.pathname[$i])
    {
    

 $path=$services.pathname[$i] 
 $path = $path.Replace("`"","")
 $path
  Check-Permissions -folder $path
  Write `n
    

    $i++
    } 


}

}


function Check-GeneralPasswordFolders{
$isFound = 0
Write-Host `n
Write-Host -BackgroundColor Red "Checking Password Folders ..."
$paths = @("c:\sysprep.inf","c:\sysprep\sysprep.xml", "%WINDIR%\Panther\Unattend\Unattended.xml","%WINDIR%\Panther\Unattended.xml")
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












