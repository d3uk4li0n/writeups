# What the Shell?

### Task 1: What is a shell?

Before we can get into the intricacies of sending and receiving shells, it's important to understand what a shell actually is. In the simplest possible terms, shells are what we use when interfacing with a Command Line environment (CLI). In other words, the common bash or sh programs in Linux are examples of shells, as are cmd.exe and Powershell on Windows. When targeting remote systems it is sometimes possible to force an application running on the server (such as a webserver, for example) to execute arbitrary code. When this happens, we want to use this initial access to obtain a shell running on the target.

In simple terms, we can force the remote server to either send us command line access to the server (a reverse shell), or to open up a port on the server which we can connect to in order to execute further commands (a bind shell).

We will be covering both of these scenarios in further detail throughout the room.

The format of this room is as follows:

The bulk of the room is made up of information, with examples given in code blocks and screenshots.
There are two VMs -- one Linux, one Windows -- in the last two tasks of the room. These can be used to practice the techniques demonstrated.
There are example practice questions in Task 13. Feel free to work through these, or follow along with the tasks as you complete them.
Without further ado, let's begin!

### Task 2: Tools

There are a variety of tools that we will be using to receive reverse shells and to send bind shells. In general terms, we need malicious shell code, as well as a way of interfacing with the resulting shell. We will discuss each of these briefly below:

---
