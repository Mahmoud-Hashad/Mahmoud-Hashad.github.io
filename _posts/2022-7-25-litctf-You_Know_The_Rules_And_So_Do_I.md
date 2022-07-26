---
title: LIT CTF - rev/You Know The Rules And So Do I
date: 2022-07-25 00:00:00 +0800
categories: [CTF, writeup]
tags: [reverse]
toc: true
---
# Lexington Informatics Tournament CTF  2022 - rev/You Know The Rules And So Do I

Lexington Informatics Tournament CTF 2022 was held from the 22nd of July Until the 25th of the month, and we have participated under the team 0xcha0s, we have managed to solve multiple challenges. this challenge was solved 10 times in the 3 days.

Were are given 2 files one is an executable and the other is a BMP image

## Discovering the binary
We were given an x64bit ELF executable.
My first thought is that the binary has hidden the flag inside the image and I will need to reverse this process.

And by decompiling the main function and analysing it:

```cpp
// open the file
stream = fopen("flag.txt", "r");
if ( !stream )
{
	puts("Error: The flag file does not exist");
	exit(0);
}

// read the flag
if ( !fread(ptr, 0x32uLL, 1uLL, stream) )
{
	puts("Error: The flag is too short");
	exit(0);
}

// convert it to bits array
for ( i = 0; i <= 49; ++i )
{
	for ( j = 0; j <= 7; ++j )
	  v22[8 * i + j] = (((int)(unsigned __int8)ptr[i] >> (7 - j)) & 1) != 0;
}
```

It will open `flag.txt` and read the flag then convert it to an array of bits.

```cpp
v20 = fopen("yougotrickrolled.bmp", "r");
v21 = fopen("yougotrickrolledChallenge.bmp", "w");
```

Then will open 2 files one contains the original image to read and the other will be written to it.

```cpp
for ( k = 0; k <= 137; ++k )
{
	fread(&v5, 1uLL, 1uLL, v20);
	fputc(v5, v21);
}
```

Then write the first 137 bytes without any changes.

```cpp
for ( m = 0; m <= 799; ++m )
{
	for ( n = 0; n <= 1199; ++n )
	{
		for ( ii = 0; ii <= 2; ++ii )
			fread(&grid[3600 * m + 3 * n + ii], 1uLL, 1uLL, v20);
	}
}
```

Then load the rest of the image in an array where `m` is the width and `n` is the height and `ii` is the color channel

```cpp
v12 = 0;
v13 = 0;
v14 = 0;
for ( jj = 0; jj <= 399; ++jj )
{
	alter(&grid[3600 * v12 + 3 * v13], v14, v22[jj]);
	v3 = v14 + 1;
	v14 = (v14 + 1) / 24;
	v14 = v3 - 24 * v14;
	if ( v22[jj] )
		++v12;
	else
		++v13;
}

unsigned __int8 alter(unsigned __int8 *grid_element, int a2, unsigned __int8 flag_bit)
{
  unsigned __int8 *result; // rax

  result = &grid_element[a2 / 8];
  *result ^= (flag_bit ^ (((int)*result >> (a2 % 8)) & 1)) << (a2 % 8);
  return result;
}
```

Now to the interesting part it will loop over our flag and change the `ith` bit at the color channel with the flag bit the bit index will increment each loop and the color channel will increment every 8 bits (single char).

If the written bit is one will change the width offset and if not will change the height offset.

And after all of this writing the new byte to the output image.

## Solver script
```python
image = open("yougotrickrolledChallenge.bmp", 'rb')
image_data = image.read()
image_data = image_data[138:]


flag = ''
flag_byte = ''
color_channel_index = 0
x = 0
y = 0

for I in range(408):
    if i > 0 and i % 8 == 0:
        flag += chr(int(flag_byte, 2))
        flag_byte = ''
        color_channel_index += 1

    image_byte = image_data[3600 * x + 3 * y + (color_channel_index % 3)]
    flag_bit = image_byte & 2 ** (i % 8)

    if flag_bit:
        x += 1
        flag_byte += '1'
    else:
        y += 1
        flag_byte += '0'



print(flag)
```

flag `LITCTF{h0n3stly_im_n0t_sur3_1f_rick_r0ll3d_mys3lf}`
