---
title: SHELL CTF - rev/One [392]
date: 2022-08-15 00:00:00 +0800
categories: [CTF, writeup]
tags: [reverse]
toc: true
---

# SHELL CTF 2022

A beginner-friendly CTF, Hosted By S.H.E.L.L

We got the `11` position on the scoreboard under team name `0xCha0s`

## One
is this challenge we have a binary file and after decompilation, we got the encryption algorithm

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-604h]
  int i; // [rsp+10h] [rbp-600h]
  int j; // [rsp+14h] [rbp-5FCh]
  int v7; // [rsp+18h] [rbp-5F8h]
  int v8; // [rsp+1Ch] [rbp-5F4h]
  int v9; // [rsp+20h] [rbp-5F0h]
  int v10; // [rsp+24h] [rbp-5ECh]
  int k; // [rsp+28h] [rbp-5E8h]
  int v12; // [rsp+2Ch] [rbp-5E4h]
  int m; // [rsp+30h] [rbp-5E0h]
  int v14; // [rsp+34h] [rbp-5DCh]
  int v15; // [rsp+34h] [rbp-5DCh]
  int v16; // [rsp+38h] [rbp-5D8h]
  int n; // [rsp+3Ch] [rbp-5D4h]
  int v18[197]; // [rsp+40h] [rbp-5D0h] BYREF
  char s1[8]; // [rsp+356h] [rbp-2BAh] BYREF
  __int16 v20; // [rsp+35Eh] [rbp-2B2h]
  char s[352]; // [rsp+360h] [rbp-2B0h] BYREF
  __int64 v22[37]; // [rsp+4C0h] [rbp-150h] BYREF
  int v23; // [rsp+5E8h] [rbp-28h]
  unsigned __int64 v24; // [rsp+5F8h] [rbp-18h]

  v24 = __readfsqword(0x28u);
  __isoc99_scanf(&unk_2020, s, envp);
  v4 = 0;
  for ( i = 0; i < strlen(s); ++i )
  {
    for ( j = s[i]; j > 0; j /= 2 )
      s[v4++ + 48] = j % 2 + 48;
    while ( (v4 & 7) != 0 )
      s[v4++ + 48] = 48;
  }
  s[v4 + 48] = 0;
  v7 = 2;
  memset(v22, 0, sizeof(v22));
  v23 = 0;
  v8 = 0;
  v9 = 0;
  while ( v9 < v4 )
  {
    *(_QWORD *)s1 = 0LL;
    v20 = 0;
    v10 = 0;
    for ( k = 0; k < v7 && v4 > v9 + k; ++k )
    {
      s1[k] = s[v9 + 48 + k];
      ++v10;
    }
    switch ( v10 )
    {
      case 1:
        if ( !strcmp(s1, "0") )
        {
          *((_BYTE *)v22 + v8) = 97;
        }
        else if ( !strcmp(s1, "1") )
        {
          *((_BYTE *)v22 + v8) = 98;
        }
        break;
      case 2:
        if ( !strcmp(s1, "00") )
        {
          *((_BYTE *)v22 + v8) = 99;
        }
        else if ( !strcmp(s1, "01") )
        {
          *((_BYTE *)v22 + v8) = 100;
        }
        else if ( !strcmp(s1, "10") )
        {
          *((_BYTE *)v22 + v8) = 101;
        }
        else if ( !strcmp(s1, "11") )
        {
          *((_BYTE *)v22 + v8) = 102;
        }
        break;
      case 3:
        if ( !strcmp(s1, "000") )
        {
          *((_BYTE *)v22 + v8) = 49;
        }
        else if ( !strcmp(s1, "001") )
        {
          *((_BYTE *)v22 + v8) = 50;
        }
        else if ( !strcmp(s1, "010") )
        {
          *((_BYTE *)v22 + v8) = 51;
        }
        else if ( !strcmp(s1, "011") )
        {
          *((_BYTE *)v22 + v8) = 52;
        }
        else if ( !strcmp(s1, "100") )
        {
          *((_BYTE *)v22 + v8) = 53;
        }
        else if ( !strcmp(s1, "101") )
        {
          *((_BYTE *)v22 + v8) = 54;
        }
        else if ( !strcmp(s1, "110") )
        {
          *((_BYTE *)v22 + v8) = 55;
        }
        else if ( !strcmp(s1, "111") )
        {
          *((_BYTE *)v22 + v8) = 56;
        }
        break;
      default:
        *((_BYTE *)v22 + v8) = 57;
        break;
    }
    v9 += v10;
    ++v8;
    v7 = (v7 + 1) % 4;
  }
  v12 = 0;
  for ( m = 0; m < v8; m += 2 )
  {
    if ( *((char *)v22 + m + 1) <= 47 || *((char *)v22 + m + 1) > 57 )
      v14 = *((char *)v22 + m + 1) - 97;
    else
      v14 = *((char *)v22 + m + 1) - 48;
    if ( *((char *)v22 + m) <= 47 || *((char *)v22 + m) > 57 )
      v15 = 16 * (*((char *)v22 + m) - 97) + v14;
    else
      v15 = 16 * (*((char *)v22 + m) - 48) + v14;
    v18[v12++ + 96] = v15;
  }
  qmemcpy(v18, "R", 0x174uLL);
  v16 = 0;
  for ( n = 0; n <= 78; ++n )
  {
    if ( v18[n] == v18[n + 96] )
      ++v16;
  }
  if ( v16 == 79 )
    puts("you're good at this!");
  else
    puts("nope, that's not it.");
  return 0;
}
```

that by create a reveres script for it you got the flag
```python
arr = [0x52,0x91,0x41,0x91,0x36,0x90,0x44,0x90,0x27,0x91,0x42,0x91,0x36,0x91,0x24,0x90,0x26,0x91,0x44,0x90,0x36,0x91,0x38,0x90,0x52,0x91,0x41,0x90,0x52,0x90,0x52,0x90,0x45,0x91,0x48,0x91,0x45,0x91,0x24,0x90,0x26,0x91,0x27,0x90,0x46,0x91,0x27,0x90,0x58,0x90,0x47,0x90,0x35,0x90,0x27,0x90,0x37,0x91,0x44,0x90,0x46,0x90,0x44,0x90,0x32,0x91,0x46,0x90,0x52,0x90,0x27,0x90,0x57,0x91,0x44,0x91,0x36,0x90,0x47,0x90,0x58,0x90,0x42,0x90,0x52,0x91,0x56,0x90,0x46,0x90,0x46,0x91,0x54]

lookup_table = {
    97:"0",
    98:"1",
    99:"00",
    100:"01",
    101:"10",
    102:"11",
    49:"000",
    50:"001",
    51:"010",
    52:"011",
    53:"100",
    54:"101",
    55:"110",
    56:"111",
}

c = 2
bits = ''
for i in arr:
    m = [i // 16, i % 16]

    for j in range(2):
        if c == 2:
            m[j] = m[j] + 97

        elif c == 3:
            m[j] = m[j] + 48

        elif c == 1:
            m[j] = m[j] + 97

        elif c == 0:
            m[j] = 57
            c = (c + 1) % 4
            continue

        bits += lookup_table[m[j]]
        c = (c + 1) % 4


flag_bytes = [bits[i:i+8] for i in range(0, len(bits), 8)]
flag = ''.join(chr(int(i[::-1],2)) for i in flag_bytes)
print(flag)

```

flag `shellctf{s0Me_b4S3_c0nVer51on5_4_U}`
