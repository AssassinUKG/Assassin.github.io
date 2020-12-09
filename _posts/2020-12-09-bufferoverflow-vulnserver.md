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
> Basic EIP Bypass (vulnserver.exe)    
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
**Vulnserver** - Download vulnserver and the 'essfunc.dll' (make sure they are together in a folder)

## Spiking


## Fuzzing
Fuzzing is to test the application is veunerable on the found exploitable input (We need to send enough data to crash the application)
Fuzzing can be done manually or with help from 


