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

### Kali app updates
* [Metasploit update](#metasploit)

### Kali
* [Tips and Tricks](#tips-and-tricks)


## Kali app updates
### Metasploit
Remove old metasploit 
```console
sudo apt remove metasploit-framework -y
```
Install new version, Run 'msfconsole' after install
```console
sudo curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```


## Tips and Tricks
### Chisel Quick guide 
<details>
  <summary>Install Chisel - Click to expand!</summary>

* cd to /opt
```console
cd /opt
```
* clone the repo
```console
git clone https://github.com/jpillora/chisel.git
```
* cd to the cloned repo
```console
cd chisel
```
sync go vendor modules, seems to be needed to build for windows
```console
go mod vendor
```
build Linux binary:
```console
go build -ldflags "-s -w"
```
build Windows binary
```console
env GOOS=windows GOARCH=amd64 go build -o chisel-x64.exe -ldflags "-s -w"
```
  
</details>




