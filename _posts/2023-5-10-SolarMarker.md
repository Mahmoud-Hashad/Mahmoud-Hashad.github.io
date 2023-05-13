---
title: SolarMarker
date: 2023-05-10 00:00:00 +0800
categories: [Malware, stealer]
tags: [real_sample, .net, dll]
toc: true
---


# Initial assessment

Using `pestudio`
MD5: ed629af9a127724d64185a26d00ae62d

File type: 32bit .NET DLL  
Compiler stamp: `Mon Feb 22 17:24:02 2021 | UTC`
entry point: 0x0002BECE

## Imports

![image 1](/assets/img/posts/solarmarker/1.png)

some imports flagged by `pestudio` that are related to security, reconnaissance and network.

## Exports 

No Exports 

## Strings 

Some interesting strings include like function names and possible C2 IP
```
GetEnvironmentVariable
GetEnvironmentVariable
ToBase64String
FromBase64String
ToBase64String
FromBase64String
GetComputerName
GetUserName
GetComputerName
GetUserName
POST
HttpWebRequest
HttpWebRequest
WriteAllText
WriteAllBytes
WriteAllText
WriteAllBytes
Process
Process
WMI
Run
set
get
add
Select
Start
Create
Write
Delete
Add
Replace
Select
Start
Create
Write
Delete
Replace
powershell
http://5.254.118.242
GetWorkGroup
HexToString
GetWinVersion
GenRandomString
EncryptXor
EncryptStr
DecryptRaw
DecryptStr
DestAddr
SymmetricKey
Win32_ComputerSystem.Name='{0}'Workgroup
Workgroup
NT 3.51
NT 4.0
2000
Vista
8.1
Windows 
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ
userprofile
application/json
{"action":"ping","
":"
","pc_name":"
","os_name":"
","arch":"
x86
x64
","rights":"
User
Admin
","version":"
","
,"protocol_version":1,"__waste__":"
status
file
task_id
type
exe
ps1
temp
{"action":"get_file","hwid":"
","task_id":"
","protocol_version": 1,"__waste__":"
{"action":"change_status","hwid":"
","is_success":true,"protocol_version":1,"__waste__":"
-ep bypass -command "iex(get-content '')"command
')"command
command
-ep bypass -command ""
MX-2UwmTIWFueMPScRNI8KiM9Zx4RA390CFCAlq5
-0123456789e+-.0123456789e+true
-.01234567ineristing89e+true
\AppData\Roaming\solarmarker.dat
```


# Static Analysis

open the file in `dnspy`, at Namespce Z and Class Z

from the first look noticed that the sample contain the same block of code that create a process which will do nothing related to the sample and this make the analysis harder

![image 2](/assets/img/posts/solarmarker/2.png)

So i used `de4do` but it didn't solve this problem so i  copied the code to a text editor and using some regex to clean it up and remove all the unwanted code 

Start our analysis at the `Run` method 

![image 3](/assets/img/posts/solarmarker/3.png)

it call `Z.Configuration` and `Z.GetHWID` 

![image 4](/assets/img/posts/solarmarker/4.png)

now this is the same url found in strings and Symmetric key will be used for encryption/decryption of the C2 communication 

and the GetHWID get the value from the file at path and if not found it will create it and set it to 32bytes of random chars this a strong host based IoC 

![image 5](/assets/img/posts/solarmarker/5.png)

continue the `Run` function it start collection info about the infected device and format at in a string like json 
```cs 
string data2 = string.Concat(new string[]
{
"{\"action\":\"ping\",\"",
"hwid",
"\":\"",
hwid,
"\",\"pc_name\":\"",
Z.GetComputerName(),
"\",\"os_name\":\"",
Z.GetWinVersion(),
"\",\"arch\":\"",
Z.Is64x() ? "x64" : "x86",
"\",\"rights\":\"",
Z.IsAdmin() ? "Admin" : "User",
"\",\"version\":\"",
configuration.AppVer,
"\",\"",
"workgroup",
"\":\"",
Z.GetWorkGroup(),
" | ",
"win32_computersystem",
"domain",
"\",\"",
"dns",
"\":",
(Z.WMI("win32_computersystem", "partofdomain").ToLower() == "false") ? "0" : "1",
",\"protocol_version\":1,\"__waste__\":\"",
Z.GenRandomString(random.Next(512)),
"\"}"
});
```
names of the function are exactly what they are doing so no need to explain 

![image 6](/assets/img/posts/solarmarker/6.png)
_Image 6_


then it will encrypt the string using `EncryptStr` and send it to the C2 using `Req` and decrypt the response using `DecryptStr` and convert it to json 

![image 7](/assets/img/posts/solarmarker/7.png)
_Image 7_

![image 8](/assets/img/posts/solarmarker/8.png)
_Image 8_

the encryption and decryption are simple xor and base64 conversion 

![image 9](/assets/img/posts/solarmarker/9.png)
_Image 9_

and the `Req` sends a post request to the C2 and get the response 

![image 10](/assets/img/posts/solarmarker/10.png)
_Image 10_

now if the response status is `ps1` it will write poweshell file and execute it in a new process  
the respond with the status success whether the file run or not  

![image 11](/assets/img/posts/solarmarker/11.png)
_Image 11_

and if status is `exe` it will write an exe file and run it the same idea as `ps1`

![image 12](/assets/img/posts/solarmarker/12.png)
_Image 12_

and if status is `command` it will run a PS command without writing it to a file 

![image 13](/assets/img/posts/solarmarker/13.png)
_Image 13_

and if the C2 is down will do to the next IP but in our case it only have one IP  and sleep for at least 20 seconds 


# IoC

## Host Based IoC

File at `<USER_PROFILE>\AppData\Roaming\solarmarker.dat`

## Network Based IoC

IP `5.254.118.242`
