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
Command: generic_send_tcp IP port command.spk 0 0
```
After you utilize the command.spk, look to see if there's an Access Violation in Immunity, if there is not, edit the command within the command.spk to a different one and retest. 

## Fuzzing
Fuzzing is to test the application is veunerable on the found exploitable input (We need to send enough data to crash the application)
Fuzzing can be done manually or with help from 


