---
title: Unpaking Loki
date: 2023-05-13 00:00:00 +0800
categories: [Malware, Unpacking]
tags: [real_sample, exe, Loki, 0x32dbg]
toc: true
---

# Initial Assessment 

## Sample Info: 
MD5: `b66eb4bcb2860ef48afbc1378e1ae545`
File Type: PE32
Compiler Time Stamp: 2016-03-29 23:03:35

## Sections 

![image 1](/assets/img/posts/loki/1.png)

contains abnormal section name 

## Imports

![image 2](/assets/img/posts/loki/2.png)

a lot of suspicious imports related to registries and internet connection but nothing related to cryptography 

## Strings and  Resources 
No important strings or resources was found in the sample 

## Entropy

![image 3](/assets/img/posts/loki/3.png)

And now we sure that the sample is packed 


# Unpacking using x32gdb
Start by adding break point at virtualalloc and virtualprotect
```
bp VirtualAlloc
bp VirtualProtect
```

and hit run `f9` to get to the entrypoint and once more to hit one of our breakpoints 

It hit VirtualAlloc 

![image 4](/assets/img/posts/loki/4.png)

i will follow the jump to change the breakpoint of the `VirtualAlloc` from the beginning to the `ret` statement

![image 5](/assets/img/posts/loki/5.png)

now when the breakpoint is hit 
Imgs

![image 6](/assets/img/posts/loki/6.png)

we can right click on the address and follow it in Memory Dump 1
Then hit run again now and the same break point in triggered again when when looking at Dump 1 

![image 7](/assets/img/posts/loki/7.png)

Dump 1 looks like it contains a shellcode 
follow the new address at Dump 2 and hit run
and the scenario repeat itself new memory is allocated and Dump 2 filled with some bytes that maybe a shellcode

![image 8](/assets/img/posts/loki/8.png)

follow the new memory at Dump 3 and run 
and again new memory and the old is filled with same data as Dump 2

![image 9](/assets/img/posts/loki/9.png)

follow new memory at Dump 4 and run 

![image 10](/assets/img/posts/loki/10.png)

and now a new memory to allocate but the old memory is not written yet  hit a run again it allocate a new memory the same address as the one we follow in Dump 4 so maybe this region was freed in the middle of the execution 

follow the new address at Dump 1  and run 

now we hit virtual protect 

![image 11](/assets/img/posts/loki/11.png)

and the memory at Dump 1 is filled with PE File 

now we can right click on the address and follow in memory map

and from memory map right click and dump to file 

![image 12](/assets/img/posts/loki/12.png)

Now if we look at the unpacked file it is a valid PE32 file and contains more suspicious strings and imports 
