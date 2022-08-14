---
title: SHELL CTF - rev/Tea [268]
date: 2022-08-15 00:00:00 +0800
categories: [CTF, writeup]
tags: [reverse]
toc: true
---

# SHELL CTF 2022

A beginner-friendly CTF, Hosted By S.H.E.L.L

We got the `11` position on the scoreboard under team name `0xCha0s`

And got first blood on this challange ;)


# tea
analyzing the main function it ask the user for the flag then call another 4 functions

```c
addSugar();
addTea();
addMilk();
strainAndServe();
```

walking threw each one of the them

### addSugar
spilt odd index chars from the even index chars then concatinate them together

### addTea
will perform some kind of subtraction encryption

### addMilk
will split the string and concatinate it with diffrent order

### strainAndServe
check if the result is correct


writing python script to reverse all of this
```python
enc_flag = [104, 108, 96, 99, 78, 89, 101, 96, 93, 109, 37, 53, 48, 103, 89, 104, 117, 103, 111, 119, 126, 51, 52, 105, 82, 59, 99, 114, 99, 55, 53, 105]

for i in range(32 >> 1):
    enc_flag[i] -= 3 * int(i / -2)

for i in range(32 >> 1, len(enc_flag)):
    enc_flag[i] -= int(i / 6)


flag_l = enc_flag[0: len(enc_flag) // 2]
flag_r = enc_flag[len(enc_flag) // 2:]

flag = ''
for i in range(16):
    flag += chr(flag_r[i]) + chr(flag_l[i])

print(flag)

```

flag `shellctf{T0_1nfiNi7y_4nD_B3y0nd}`
