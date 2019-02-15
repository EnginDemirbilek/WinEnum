# WinEnum
Powershell script to automate finding privilege escalation vectors in windows environments.



## USAGE

First import it as module.
```
PS C:\Users\Hyaloid\Desktop> Import-Module winenum.ps1
```

**General Information**

Checking general information about system which are Operating System, Number of logical processors, Current user, Computer name and ip addresses machine has.
Function name: **Check-General**


```
PS C:\Users\Hyaloid\Desktop> Check-General


General Info
[+] Operating System= Windows Server 2012
[+] Number Of Processors= 2 2
[+] Current User= Hyaloid
[+] Computer Name= DC01
[+] IP Addresses of Machine
10.1.1.1
```

**Check if Machine is virtual machine or not**

```
PS C:\Users\Hyaloid\Desktop> Check-isVirtual
[+] Machine Type= Virtual:  VMware, Inc.PS C:\Users
```

**Check Local Admins**
```
PS C:\Users\hyaloid\Desktop> Check-LocalAdmins


[+] Local Admins

Administrator marry.jane
Domain Admins
Enterprise Admins

```

**Check Domain**
Gather information about domain. Domain admins, domain name.
```
PS C:\Users\Hyaloid\Desktop> Check-Domain
Domain Info
[+] Domain= PENTESTLAB.com
[+] Domain Admins= Administrator            marry.jane
```

**Check HotFix Updates**
Check hotfix update for kernel exploitation (i'm still working an exploit suggester module)
```
PS C:\Users\hyaloid\Desktop> Check-SecurityUpdates
Security Updates



HotFixID  InstalledOn        
--------  -----------        
KB4230204 3.11.2018 00:00:00 
KB4456655 4.11.2018 00:00:00 
KB4465663 14.11.2018 00:00:00
KB4471331 6.12.2018 00:00:00 
KB4477137 13.12.2018 00:00:00
KB4480979 12.01.2019 00:00:00
KB4485449 13.02.2019 00:00:00
KB4487038 13.02.2019 00:00:00
KB4487017 13.02.2019 00:00:00

```


**Check AlwaysInstallElevated Registery Key**
Check alwaysinstallelevated key to local privilege escalation.
```
PS C:\Users\Administrator\Desktop> Check-AlwaysInstallElevated
Checking AlwaysInstallElevated Registery
[+]! Host may be vulnerable to AlwaysInstallElevated Exploitation, checking registery keys for grant
[+][+][+] Vulnerability granted !!! Check: https://github.com/EnginDemirbilek/WinEnum/AlwaysInstallElevated for exploitation.
```


**Check Unquoted Service Paths**
Check unqoted service paths to local privilege escalation.

```
PS C:\Users\hyaloid\Desktop> Check-UnquotedServicePath
Checking unquoted service paths
[+][+]Vulnerable services found, check http://blabla for "possible" exploitation

state   name                       pathname                                                                        startmode
-----   ----                       --------                                                                        ---------
Running ASLDRService               C:\Program Files (x86)\ASUS\ATK Package\ATK Hotkey\AsLdrSrv.exe                 Auto     
Running ATKGFNEXSrv                C:\Program Files (x86)\ASUS\ATK Package\ATKGFNEX\GFNEXSrv.exe                   Auto     
Stopped DevActSvc                  C:\Program Files (x86)\ASUS\ASUS Device Activation\DevActSvc.exe                Manual   
Stopped Kingsoft_WPS_UpdateService C:\Program Files (x86)\Kingsoft\WPS Office\10.1.0.5644\wtoolex\wpsupdatesvr.exe Auto     

```

**Check Permissions of Service Executables**
Check permission of service executables(only for everyone and BUILTIN\Users) to local privilege escalation.

```
PS C:\Users\Hyaloid\Desktop> Check-ServiceExecutablePermissions
Checking permissions of service executables.


C:\Program Files\VMware\VMware Tools\TPAutoConnSvc.exe

IdentityReference                                                                                      FileSystemRights
-----------------                                                                                      ----------------
Everyone                                                                                    ReadAndExecute, Synchronize


C:\Program Files\VMware\VMware Tools\TPVCGateway.exe
Everyone                                                                                    ReadAndExecute, Synchronize


C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
Everyone                                                                                    ReadAndExecute, Synchronize


C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
Everyone                                                                                    ReadAndExecute, Synchronize


C:\Program Files\VMware\VMware Tools\vmacthlp.exe
Everyone                                                                                    ReadAndExecute, Synchronize


C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\CommAmqpListener.exe
Everyone                                                                                    ReadAndExecute, Synchronize


C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\ManagementAgentHost.exe
Everyone                                                                                    ReadAndExecute, Synchronize

```

**Check Permissions of Executables Manually (In case automation can't detect all of them)**


Only for BUILTIN\Users and everyone.
```
PS C:\Users\hyaloid\Desktop> Check-Permissions "C:\Program Files (x86)\ASUS\ATK Package\ATK Hotkey\AsLdrSrv.exe "

IdentityReference            FileSystemRights
-----------------            ----------------
BUILTIN\Users     ReadAndExecute, Synchronize


```

Thats it for now. Many is coming ..






