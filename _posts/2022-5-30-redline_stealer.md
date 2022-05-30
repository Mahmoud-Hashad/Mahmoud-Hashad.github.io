---
title: RedLine Stealer
date: 2022-05-30 00:00:00 +0800
categories: [Malware, Spyware]
tags: [read_sample, .net, exe]     # TAG names should always be lowercase
toc: true
---
# Overview
Sample URL: [bazaar.abuse](https://bazaar.abuse.ch/sample/05d57f5a9de385039f7c3b130325595f176d7181e205681b22a1ad9e4f46951b/)

`RedLine` is a stealer malware that collects all information about the victim as passwords and credit card numbers.

In this analysis, the goal is to discover the capabilities of the `RedLine` and its execution flow.
    if tarfile.is_tarfile(path):

# Basic Static Analysis

Using `Detect-it-easy` and `PeID`:
- 32bit
- .net executable
- not packed

Checking strings show some clear text this file was not obfuscated

# Advanced Static Analysis

## deobfuscation

Just to make sure that the file is clear

```shell
de4dot -f sample.exe clean_sample.exe
```
`de4dot` fixed some strings but not the huge deal


## Source Code Analyzing

Opening it int `dnspy`. The original EXE name was `happy.exe`

Looking at the `main` method inside the `program` class to start following the execution.

The first thing it Creates a new object of class `entrypoint` inside this class constructor some important values are initialized

```c#
this.IP = "178.159.38.57:60668";
this.ID = "build";
this.Message = "";
this.Key = "";
```



### Connecting to C2

Then run the `execute` method and pass the `entrypoint` instance a parameter

It will try to use the decryption method taking a string and key to get the IP

The method works as follows

- base64 decode the string
- xor the decoded string with the key
- base64 decode the xor string
- if any exception is raised the original string will be returned

And because the `IP` is not encrypted it will fail and return the same string

This method would be important if the `IP` was encrypted


Continue with the function create `EndpointConnection` object to create a channel with C2 and check the connection establishment



### Recive Setting

Send a request to c2 to send the settings that will control the execution flow of the malware


```c#
ScanningArgs settings = new ScanningArgs();
while (!endpointConnection.TryGetArgs(out settings))
{
  if (!endpointConnection.TryGetConnection())
  {
    throw new Exception();
  }
  Thread.Sleep(1000);
}
```


`ScanningArgs` class attributes that will hold the settings

```
ScanBrowsers
ScanFiles
ScanFTP
ScanWallets
ScanScreen
ScanTelegram
ScanVPN
ScanSteam
ScanDiscord
ScanFilesPaths
BlockedCountry
BlockedIP
ScanChromeBrowsersPaths
ScanGeckoBrowsersPaths
```


### Collect Information
Before starting to collect data the malware check if this device is from the blocked country or blocked IPs that are located in the setting if not it will start gathering all the information

This is the content of the scan result that will be sent to C2

- Country
- City
- IPv4
- ZipCode
- Hardware -> md5 hash for `Environment.UserDomainName + Environment.UserName + SystemInfoHelper.GetSerialNumber()` and replace `-` with space
- FileLocation -> path of the executed binary
- Language -> keyboard layouts
- TimeZone -> timezone :)
- OSVersion -> windows prodact name + (32 or 64)bit
- MachineName -> from `Environment.UserName`
- ScanDetails
  - SystemHardwares -> List
    - for CPUs and GPUs:
      - Name
      - Counter -> number of cores
      - HardType -> 0 indicate CPU and 1 for GPU
    - for RAM:
       - Name is `Total of RAM`
       - Counter -> ram size
       - HardType -> 1 same as GPU
  - InstalledBrowsers -> List
    - NameOfBrowser
    - PathOfFile -> absloute path of the browser
    - Version
  - Softwares -> List
    - name\[version\]
  - SecurityUtils -> List
    - will search at the security center and security center2 for `Antivirus`, `Anti-spyware` and `Firewall` products
    - the list contains the display name of the found product
  - Processes -> List
    - follows this format
    - ID: {Process_Id}, Name: {Process_Name}, Commandline: {commandline that start the process}
  - AvailableLanguages -> List of all installed input languages
  - MessageClientFiles -> List of all files in user desktop
  - Browsers: List
    - BrowserName
    - BrowserProfile
    - Logins -> List
      - URL
      - Username
      - Password
    - Coockies  -> List
      - Host
      - Http
      - Path
      - Secure
      - Expires
      - Name
      - Value
    - Autofills -> List
      - Name
      - Value
    - CC -> list of credit cards
      - HolderName
      - Month ->  expiration month
      - Year ->  expiration year
      - Number
  - ScannedFiles -> List
    - list the files like MessageClientFiles but it retrieves the dirs to scan from `settings.ScanFilesPaths`
  - FtpConnections -> List
    - URL
    - Username
    - Password
  - ScannedWallets -> List
    - list of all founded wallets
    - supported wallets: Armory, atomic, Coinomi, Electrum, Ethereum, Exodus, Guarda, jaxx, and a general rule to match wallets
    - supported Browser Extensions: Yoroi, Tronlink, NiftyWallet, Metamask, MathWallet, Coinbase, BinanceChain, BraveWallet, GuardaWallet, EqualWallet, JaxxxLiberty, BitAppWallet, iWallet, Wombat, AtomicWallet, Mewcx, GuildWallet, SaturnWallet, RoninWallet
  - GameChatFiles -> List
    - if `settings.ScanDiscord` is true
    - contains a list of discord tokens
  - GameLauncherFiles -> List
    - if `settings.ScanSteam` is true
    - list of config files of steam
  - Nord
    - if `settings.ScanVPN` is true
    - just an empty list
  - Open
    - if `settings.ScanVPN` is true
    - for OpenVPN
  - Proton
    - if `settings.ScanVPN` is true
    - for ProtonVPN
- Resolution -> screen size
- Monitor -> Screenshot of the screen
- ReleaseID -> for our case `build`
- SeenBefore -> check if the directory `{LocalApplicationData}\Yandex\YaAddon` exist and if not create it


### Get Remote Tasks
After sending the scanned data. `RedLine` Check if there was any update.

include those 4 methods

- CommandLineUpdate
- DownloadUpdate
- DownloadAndExecuteUpdate
- OpenUpdate

# Advanced Dynamic Analysis

Running the sample at [any.run](https://any.run/)

It sends 4 requests to C2 as shown in the figure

![C2-connections](/assets/img/posts/redline/connections.png)
_C2 Connections_

Examining the requests `redline` uses `SOAP` protocol to communicate with C2 and the data is sent as `XML`.


![checkconn](/assets/img/posts/redline/checkconn.png)
_Check connection request_

## Settings

Inspecting the second request that retrieves settings and examining the response

You can check the file from [here](/assets/img/posts/redline/settings.xml)

The settings for this sample are
```c#
ScanBrowsers = true
ScanFiles = true
ScanFTP = true
ScanWallets = true
ScanScreen = true
ScanTelegram = true
ScanVPN = true
ScanSteam = true
ScanDiscord = true
ScanFilesPaths = [
    "%userprofile%\Desktop|*.txt,*.doc*,*key*,*wallet*,*seed*|0",
    "%userprofile%\Documents|*.txt,*.doc*,*key*,*wallet*,*seed*|0"
]
BlockedCountry = []
BlockedIP = []
ScanChromeBrowsersPaths = [
    "%USERPROFILE%\AppData\Local\Battle.net",
    "%USERPROFILE%\AppData\Local\Chromium\User Data",
    "%USERPROFILE%\AppData\Local\Google\Chrome\User Data",
    "%USERPROFILE%\AppData\Local\Google(x86)\Chrome\User Data",
    "%USERPROFILE%\AppData\Roaming\Opera Software\",
    "%USERPROFILE%\AppData\Local\MapleStudio\ChromePlus\User Data",
    "%USERPROFILE%\AppData\Local\Iridium\User Data",
    "%USERPROFILE%\AppData\Local\7Star\7Star\User Data",
    "%USERPROFILE%\AppData\Local\CentBrowser\User Data",
    "%USERPROFILE%\AppData\Local\Chedot\User Data",
    "%USERPROFILE%\AppData\Local\Vivaldi\User Data",
    "%USERPROFILE%\AppData\Local\Kometa\User Data",
    "%USERPROFILE%\AppData\Local\Elements Browser\User Data",
    "%USERPROFILE%\AppData\Local\Epic Privacy Browser\User Data",
    "%USERPROFILE%\AppData\Local\uCozMedia\Uran\User Data",
    "%USERPROFILE%\AppData\Local\Fenrir Inc\Sleipnir5\setting\modules\ChromiumViewer",
    "%USERPROFILE%\AppData\Local\CatalinaGroup\Citrio\User Data",
    "%USERPROFILE%\AppData\Local\Coowon\Coowon\User Data",
    "%USERPROFILE%\AppData\Local\liebao\User Data",
    "%USERPROFILE%\AppData\Local\QIP Surf\User Data",
    "%USERPROFILE%\AppData\Local\Orbitum\User Data",
    "%USERPROFILE%\AppData\Local\Comodo\Dragon\User Data",
    "%USERPROFILE%\AppData\Local\Amigo\User\User Data",
    "%USERPROFILE%\AppData\Local\Torch\User Data",
    "%USERPROFILE%\AppData\Local\Yandex\YandexBrowser\User Data",
    "%USERPROFILE%\AppData\Local\Comodo\User Data",
    "%USERPROFILE%\AppData\Local\360Browser\Browser\User Data",
    "%USERPROFILE%\AppData\Local\Maxthon3\User Data",
    "%USERPROFILE%\AppData\Local\K-Melon\User Data",
    "%USERPROFILE%\AppData\Local\Sputnik\Sputnik\User Data",
    "%USERPROFILE%\AppData\Local\Nichrome\User Data",
    "%USERPROFILE%\AppData\Local\CocCoc\Browser\User Data",
    "%USERPROFILE%\AppData\Local\Uran\User Data",
    "%USERPROFILE%\AppData\Local\Chromodo\User Data",
    "%USERPROFILE%\AppData\Local\Mail.Ru\Atom\User Data",
    "%USERPROFILE%\AppData\Local\BraveSoftware\Brave-Browser\User Data",
    "%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data",
    "%USERPROFILE%\AppData\Local\NVIDIA Corporation\NVIDIA GeForce Experience",
    "%USERPROFILE%\AppData\Local\Steam",
    "%USERPROFILE%\AppData\Local\CryptoTab Browser\User Data"
]
ScanGeckoBrowsersPaths = [
    "%USERPROFILE%\AppData\Roaming\Waterfox",
    "%USERPROFILE%\AppData\Roaming\K-Meleon",
    "%USERPROFILE%\AppData\Roaming\Thunderbird",
    "%USERPROFILE%\AppData\Roaming\Comodo\IceDragon",
    "%USERPROFILE%\AppData\Roaming\8pecxstudios\Cyberfox",
    "%USERPROFILE%\AppData\Roaming\NETGATE Technologies\BlackHaw",
    "%USERPROFILE%\AppData\Roaming\Moonchild Productions\Pale Moon"
]
```
{: file="settengs" }

## Scan Results

Looking at the third request that send 1.5MB Most of the data are the base64 encoded screenshot

Nothing was new all of the sent data was discussed before

You can check the file from [here](/assets/img/posts/redline/scan_result.xml)

## Remote Tasks
Analyzing the last request. No remote tasks were returned
