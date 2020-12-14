---
title: "Kali Tricks"
excerpt_separator: "<!--more-->"
author_profile: false
categories:
  - Linux
tags:
  - cheatsheet
  - kali
---


## Sections
# [Kali app updates](/Kali-app-updates)
* [Metasploit update](/metasploit)


## Kali app updates
## Metasploit
Remove old metasploit 
```console
sudo apt remove metasploit-framework -y
```
Install new version, Run 'msfconsole' after install
```console
sudo curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```


