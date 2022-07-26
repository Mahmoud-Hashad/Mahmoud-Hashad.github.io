---
title: LIT CTF - rev/codetiger-orz
date: 2022-07-25 00:00:00 +0800
categories: [CTF, writeup]
tags: [reverse]
toc: true
---
# Lexington Informatics Tournament CTF  2022 - rev/codetiger-orz
Lexington Informatics Tournament CTF 2022 was held from the 22nd of July Until the 25th of the month, and we have participated under the team 0xcha0s, we have managed to solve multiple challenges. this challenge was solved 43 times in the 3 days.

The challenge is a python script looking at it asks the user for 7 digit password to decrypt a message.

```python
from cryptography.fernet import Fernet
import base64

alphabet = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
payload = b'<some data>'


def derivePassword():
    kw = ['~#+', 'v~s', 'r~st', '%xvt#', 'st%tr%x\'t']
    userKeyInput = input('Enter the key: ')  # 7-digit integer

    try:
        retrievePasswordKey = list(map(int, list(userKeyInput)))
        # retrievePasswordKey = list(str(10*0) + len(kw[2]) + str(2**0) + len(kw[0]) + '2' + len("orz) + '0')

        ct = kw[retrievePasswordKey[0]] + kw[retrievePasswordKey[1]] + kw[retrievePasswordKey[2]] + \
            kw[retrievePasswordKey[3]] + kw[retrievePasswordKey[4]] + \
            kw[retrievePasswordKey[5]] + kw[retrievePasswordKey[6]]
        # return ROT(ct, s)
        return 'defaultplaceholderkeystringabcde'
    except:
        if max(list(map(int, list(userKeyInput)))) >= len(kw):
            print('Key digits out of range!')
        else:
            print('Invalid key format!')
        exit()


key_str = derivePassword()
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)

try:
    d = f.decrypt(payload)
except:
    print('The provided key was not correct!\nDECRYPTION FAILED.')
    exit()

solution = d.decode()  # decrypted solution
print(solution)


def ROT(ct, s):
    pt = ''
    for c in ct:
        index = alphabet.find(c)
        original_index = (index + s) % len(alphabet)
        pt = pt + alphabet[original_index]
    return pt
# s = 1 (mod 2), s = 7 (mod 11), 7 < |s| < 29
# ROT|s| used to create password ciphertext


def solutionDecrypt(cipher):
    cipher = cipher.split('\n')

    def c(l):
        b = ''
        l = l.split()
        if len(l) > 0:
            for t in l:
                if t == 'codetiger':
                    b += '1'
                elif t == 'orz':
                    b += '0'
            return chr(int(b, 2))
        else:
            return ''

    s = ''
    for l in cipher:
        s += c(l)
    return s
```

But the `derivePassword` function has a constant return no matter what you enter it will return the same value and some functions are never called like `ROT` and `solutionDecrypt`.

And some comments are interesting
- `# retrievePasswordKey = list(str(10*0) + len(kw[2]) + str(2**0) + len(kw[0]) + '2' + len("orz) + '0')` you will have to fix few erros and you will find the key `0413230`
- `# return ROT(ct, s)` and this replace the constant value the `drivePassword` return but we need to find the `s`
- `#s = 1 (mod 2), s = 7 (mod 11), 7 < |s| < 29` and from this comment you can find `s` using a loop to find the number the match all cases `s=-15`

After this you will call `solutionDecrypt` and print the result

So the script will be like:

```python
from cryptography.fernet import Fernet
import base64

alphabet = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
payload = b'<some data>'

def ROT(ct, s):
    pt = ''
    for c in ct:
        index = alphabet.find(c)
        original_index = (index + s) % len(alphabet)
        pt = pt + alphabet[original_index]
    return pt
# s = 1 (mod 2), s = 7 (mod 11), 7 < |s| < 29
# ROT|s| used to create password ciphertext

def derivePassword():
    kw = ['~#+', 'v~s', 'r~st', '%xvt#', 'st%tr%x\'t']
    userKeyInput = "0413230"  # 7-digit integer

    try:
        retrievePasswordKey = list(map(int, list(userKeyInput)))
        # retrievePasswordKey = list(str(10*0) + len(kw[2]) + str(2**0) + len(kw[0]) + '2' + len("orz) + '0')

        ct = kw[retrievePasswordKey[0]] + kw[retrievePasswordKey[1]] + kw[retrievePasswordKey[2]] + \
            kw[retrievePasswordKey[3]] + kw[retrievePasswordKey[4]] + \
            kw[retrievePasswordKey[5]] + kw[retrievePasswordKey[6]]
        return ROT(ct, -15)
       # return 'defaultplaceholderkeystringabcde'
    except Exception as e:
        print(e)
        if max(list(map(int, list(userKeyInput)))) >= len(kw):
            print('Key digits out of range!')
        else:
            print('Invalid key format!')
        exit()


key_str = derivePassword()
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)

try:
    d = f.decrypt(payload)
except:
    print('The provided key was not correct!\nDECRYPTION FAILED.')
    exit()

solution = d.decode()  # decrypted solution
print(solution)






def solutionDecrypt(cipher):
    cipher = cipher.split('\n')

    def c(l):
        b = ''
        l = l.split()
        if len(l) > 0:
            for t in l:
                if t == 'codetiger':
                    b += '1'
                elif t == 'orz':
                    b += '0'
            return chr(int(b, 2))
        else:
            return ''

    s = ''
    for l in cipher:
        s += c(l)
    return s

print(solutionDecrypt(solution))

```

the flag: `LITCTF{1m_73ry_6ad_a1_r3v_en9in33r1ing}`
