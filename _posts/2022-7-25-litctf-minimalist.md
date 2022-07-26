---
title: LIT CTF - rev/minimalist
date: 2022-07-25 00:00:00 +0800
categories: [CTF, writeup]
tags: [reverse]
toc: true
---


# Lexington Informatics Tournament CTF  2022 - rev/minimalist

Lexington Informatics Tournament CTF 2022 was held from the 22nd of July Until the 25th of the month, and we have participated under the team [0xcha0s](https://ctftime.org/team/168238), we have managed to solve multiple challenges. this challenge was solved 53 times in the 3 days.


## Discovering the binary
We are given a binary using file command reveals it is an x64bit ELF executable.
![File command](/assets/img/posts/litctf/img1.png)

Opening the file in IDA and decompiling the decompiled function looked wired and missing instructions compared to the assembly

![ida decompilation](/assets/img/posts/litctf/img2.png)
![ida asm](/assets/img/posts/litctf/img3.png)

And trying ghidra shows a better result on decompilation
![ghidra decompilation](/assets/img/posts/litctf/img4.png)

The code can be broke to 3 sections:
1. Take the flag from user
2. Doing some operations on the data
3. check if it is a valid flag

So let us dive into each one of those

### Inputting the flag

```cpp
puts("Enter the flag: ");
for (i = 0; i < 0x2f; i++) {
	flag_char = getchar();
	if (i == 0) {
		*(array + -8) = flag_char;
		array -= 8;
	}
	*(array + -8) = *(&first_arry + i * 8);
	*(array + -0x10) = *(&second_arry + i * 8);
	*(array + -0x18) = flag_char;
}
```
Cleaning the section and analysing it. the input is 47 char length string. the first char will be stored twice, and for each input char, it wil store the char after 2 bytes from 2 arrays on data section.
the result of this part is an array where each 3 bytes on this format `<first array byte> <second array byte> <flag_char>`

### Processing the flag
Cleaning the code and it reveals a simple operation using each 3bytes from the result of the last part
```cpp
not_flag = 0;
for (j = 0; j < 0x2f; j = j + 1) {
    n_1 = array[1];
    n_2 = array[2];
    n_3 = array[3];

    res = ~(n_1 | ~n_3) | ~(~n_1 | n_3);
    not_flag = not_flag | ~(~res | ~n_2) | ~(res | n_2);
    array = array + 3;
}

last_char = *array;
value = 0xffffffffffffff82;
not_flag = not_flag | ~(last_char | value) | ~(~value | ~last_char);
```

###  Flag check
It will check if the result of the prevouis part is zero

```cpp
if (not_flag == 0) {
    puts("The flag is correct.");
} else {
    puts("Wrong flag!");
}
```

## Solve
- dumping the 2 arrays
- then bute force each char of the flag the will keep `not_flag` equal to zero
- then brute force the last char

```cpp
#include <iostream>
using namespace std;

int main() {
    unsigned char x[] = { 0x87, 0xd3, 0xcc, 0xb5, 0x85, 0xe0, 0xc0, 0xa1, 0xf0, 0x83, 0xe4, 0xe8, 0xe4, 0x9a, 0xff, 0xf8, 0xe4, 0xdd, 0x8e, 0xda, 0xcc, 0x9f, 0xe8, 0xe8, 0xab, 0xf7, 0xb7, 0xa5, 0xe9, 0xf1, 0xec, 0xfc, 0x8a, 0x8f, 0xe7, 0xdd, 0x84, 0xca, 0xfa, 0x95, 0x87, 0xea, 0xc5, 0xa5, 0xe9, 0xb9, 0xff};

    unsigned char y[] = { 0x34, 0x60, 0x7a, 0x1e, 0x39, 0x4b, 0x79, 0x25, 0x58, 0x14, 0x2b, 0x48, 0x75, 0x56, 0x33, 0x63, 0x68, 0x7d, 0x10, 0x14, 0x02, 0x3f, 0x63, 0x7f, 0x64, 0x7b, 0x0d, 0x05, 0x70, 0x3a, 0x7d, 0x60, 0x0c, 0x2f, 0x29, 0x4c, 0x08, 0x41, 0x77, 0x1f, 0x1b, 0x61, 0x53, 0x35, 0x78, 0x35, 0x3f};
    string chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c";

    for (int i = 1; i < 0x2f; i++){
        for (int j = 0; j < chars.length(); j++) {

            char n_1 = x[i];
            char n_2 = y[i];
            char n_3 = chars[j];

            char not_flag = 0;
            char res = 0;

            res = ~(n_1 | ~n_3) | ~(~n_1 | n_3);
            not_flag = not_flag | ~(~res | ~n_2) | ~(res | n_2);


			if (!not_flag)
				cout << n_3;

      }
    }

    for(int i = 0; i < chars.length(); i++) {
        char val = char(0xffffffffffffff82);
        char last = chars[i];
        char not_flag = 0;
        not_flag = not_flag | ~(last | val) | ~(~val | ~last);
        if (!not_flag)
            cout << last;
    }


    return 0;
}

```
{: file="main.cpp" }

and the flag is `LITCTF{Wh0_n33ds_a11_th0sE_f4ncy_1nstructions?}`
