---
title: "Pentest Quick Cheatsheet"
excerpt_separator: "<!--more-->"
author_profile: false
categories:
  - Linux
tags:
  - cheatsheet
  - kali
---


## Metasploit Install

*remove old metasploit 
```console
sudo apt remove metasploit-framework -y
```

```console
sudo curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

