---
layout: post
title:  "Reading out of a sandbox: a CTF adventure" 
date:	2021-08-25 13:20:21 +0300
tags: [pwn, Linux, syscalls, sandbox]
---

In this blog post, I'll go through the writeup of how I and my good friend [@RobHaii](https://twitter.com/RobHaii) solved an interesting CTF challenge presented by NahamCon 2020. It was a simple implementation of a system call sandbox, and the solution was to bypass the sandbox by using already whitelisted system calls. 

## What are system calls? 
System calls are kernel sub-routines which allow user-space programs to request a specific service on behalf of the kernel such as network and file I/O, process creation and so on. Whenever a program calls *open()*, *read()*, *write()* or any other library function, an underlying system call is invoked, with the exception of [virtual system calls](https://man7.org/linux/man-pages/man7/vdso.7.html).

Most system calls are abstracted away from the programmer by glibc wrappers, although some of them have to be called directly (such as *futex()*). Without getting into too much details, whenever a system call is invoked, a context switch is made from the user space to kernel space by either using a legacy software interrupt, or newer fast system call methods, such as *sysenter()* and *syscall()* for 32 and 64bit systems.

A very good explanation of Linux system calls internals is found [here](https://packagecloud.io/blog/the-definitive-guide-to-linux-system-calls/).

## What about sandboxes? 
A sandbox is a security mechanism which restricts a process to a set of whitelisted actions it can perform. Although sanbox implemenations are popularized by web browsers, they are deployed in other contexts such as anti-viruses, PDF readers, mobile apps, containers and such. Even virtual machines can be considered as sandboxes where the host machine is protected from malicious actions happening in the VM. Sandboxes provide additional security protection because they restrict processes regardless of other access control mechanisms such as user IDs and permissions. 

Userspace applications can be restricted to certain system calls in modern operating systems by mechanisms such as [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) in Linux and [pledge](https://man.openbsd.org/pledge.2) in OpenBSD. 

## Sytem call-as-a-Service 
The aptly named challenge required the player to connect to a service which invokes the CTF binary. Upon donwloading and inspecting the binary, it turned out to be a 64bit ELF unstripped executable with debug symbols. Loading the executable in IDA pro disassembler and decompiling main results in the following pseudo-code. 
### main()

```C 
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 sysno; // [rsp+8h] [rbp-48h] BYREF
  __int64 v4; // [rsp+10h] [rbp-40h] BYREF
  __int64 v5; // [rsp+18h] [rbp-38h] BYREF
  __int64 v6; // [rsp+20h] [rbp-30h] BYREF
  __int64 v7; // [rsp+28h] [rbp-28h] BYREF
  __int64 v8; // [rsp+30h] [rbp-20h] BYREF
  __int64 v9; // [rsp+38h] [rbp-18h] BYREF
  __int64 v10; // [rsp+40h] [rbp-10h]
  unsigned __int64 v11; // [rsp+48h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  puts("Welcome to syscall-as-a-service!\n");
  while ( 1 )
  {
    printf("Enter rax (decimal): ");
    __isoc99_scanf("%ld", &sysno);
    if ( (unsigned int)blacklist(sysno) )
    {
      puts("Sorry syscall is blacklisted\n");
    }
    else
    {
      printf("Enter rdi (decimal): ");
      __isoc99_scanf("%ld", &v4);
      printf("Enter rsi (decimal): ");
      __isoc99_scanf("%ld", &v5);
      printf("Enter rdx (decimal): ");
      __isoc99_scanf("%ld", &v6);
      printf("Enter r10 (decimal): ");
      __isoc99_scanf("%ld", &v7);
      printf("Enter r9 (decimal): ");
      __isoc99_scanf("%ld", &v8);
      printf("Enter r8 (decimal): ");
      __isoc99_scanf("%ld", &v9);
      v10 = syscall(sysno, v4, v5, v6, v7, v9, v8);
      printf("Rax: 0x%lx\n\n", v10);
    }
  }
}
```

After printing its greeting message, it goes into an infinite loop, where it reads seven long integers from the network and puts them in separate variables. It then checks the first read number (put in a variable called *sysno*) and gives it to a function called *blacklist()*, and finally based on the return value from the *blacklist()* calls, it either calls a function *syscall()* with our data-holding variables or fails with an error message. 

## Syscall numbers and calling conventions 
We will come to the above function later. Before that, let's talk a little about calling conventions. Calling conventions are conventions which specify called code interfaces, such as the order of parameters passed to the callee, how parameters are passed (either by pushing on the stack or by registers or both), how return values are returned to the caller, which registers the called code must preserve for the caller code, and how stack is prepared and restored before and after the call. Calling conventions vary across different processor architectures, across different compilers in the same architecture, and even between usermode and kernel interfaces. 

Coming to the challenge, after recieving the long integers from the user, it makes a call to [*syscall()*](https://man7.org/linux/man-pages/man2/syscall.2.html). *syscall()* is a small library function which invokes system calls by using the appropriate system calls number. It is useful to invoke system calls which do not have glibc wrappers. Its declaration is:  
```C 
long syscall(long number, ...);
```
It accepts a syscall number, and variable number of arguments, and returns a *long* value from the call. The variable arguments are passed to the called system call as parameters. Every system call has a unique syscall number which can be passed to *syscall()*. A system call can, and usually has different syscall number for various architectures. The list of system calls with their syscall numbers across different architectures can be found [here](https://syscalls.w3challs.com/). 

Bringing back calling conventions, the kernel interface of X86_64 Linux compilers states that parameters are passed by **RDI, RSI, RDX, R10, R8 and R9** in order to system calls. For example, the [*write()*](https://man7.org/linux/man-pages/man2/write.2.html) system call has a unique syscall number of 1 in X86_64 and the following parameters. 
```C 
ssize_t write(int fd, const void *buf, size_t count);
```
Therefore, *fd* parameter will be passed by *RDI*; *buf* will be passed by *RSI*; *count* will be passed by *RDX*. *R10*, *R8* and *R9* will be set to zero. 

Thus, when invoking *write()* by using *syscall()*, it will be like this: 
```C 
syscall(1, %RDI, %RSI, %RDX)
```

## The sandbox 
Knowing this, the [SaaS binary](#main) makes more sense now. It accepts a syscall number and puts it in *sysno*, accepts upto 6 arguments for the system call,  and calls *syscall()*, and returns the return value of the system call back to us. But before the invocation, it calls *blacklist()* with *sysno* as a parameter, and based on the return value, it succeeds to invoke our system call or fails with the message "Sorry syscall is blacklisted". Let's see the blacklisting function. 
```C 
__int64 __fastcall blacklist(__int64 a1)
{
  unsigned int i; // [rsp+1Ch] [rbp-44h]
  __int64 v3[8]; // [rsp+20h] [rbp-40h]

  v3[7] = __readfsqword(0x28u);
  v3[0] = 59LL;
  v3[1] = 57LL;
  v3[2] = 56LL;
  v3[3] = 62LL;
  v3[4] = 101LL;
  v3[5] = 200LL;
  v3[6] = 322LL;
  for ( i = 0; i <= 6; ++i )
  {
    if ( a1 == v3[i] )
      return 1LL;
  }
  return 0LL;
}
```
It compares our syscall number to a list of blacklisted numbers, and it matches, it will return 1. The syscall numbers listed correspond to [execve()](https://man7.org/linux/man-pages/man2/execve.2.html), [fork()](https://man7.org/linux/man-pages/man2/fork.2.html), [clone()](https://man7.org/linux/man-pages/man2/clone.2.html), [kill()](https://man7.org/linux/man-pages/man2/kill.2.html), [ptrace()](https://man7.org/linux/man-pages/man2/ptrace.2.html), [tkill()](https://man7.org/linux/man-pages/man2/tkill.2.html), and [timerfd_create()](https://man7.org/linux/man-pages/man2/timerfd_create.2.html)(32bit). These system calls are associated with process and thread cloning, execution of images, killing processes and threads, and timer notification. Therefore, we can't do anything related to these tasks through the SaaS because of the blacklisting function. 

## Exploitation

The plan is to read the file *flag.txt*. Since, we can't execute commands such as */bin/sh -c 'cat flat.txt'* using system calls such as exec and fork. so, we will use other system calls to open the file, read its contents and and send it back to us using allowed system calls. 

The first thing to do, therefore, would be to open the file. Searching for the man pages for system calls for opening files (or searching google) will lead us to use *[open()](https://man7.org/linux/man-pages/man2/openat.2.html)*. open() system call is declared as such. 
```C 
int open(const char *pathname, int flags);
``` 
So, we have to provide *pathname*, in our case *flag.txt* as a pointer to C string. But we don't have a pointer to "flag.txt", so we have to manually write it into a controlled memory region and pass the address of that region to open(). 

After googling about linux system calls to allocate a memory region, we will come up with *[mmap()](https://man7.org/linux/man-pages/man2/mmap.2.html)*. The parameters and return value of mmap() is as belows. 
```C 
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
``` 
mmap() creates  a  new  mapping  in the virtual address space of the calling process. It accepts a size paramter by *length*, and starting memory address to map by *addr*. If *addr* is null, the kernel will choose a page-alligned memory region randomly. The *prot* parameter is the protection flags. For our case, we will choose (PROT_READ|PROT_WRITE) which is 0x3. The *flags* is mapping flags, and we will select (MAP_PRIVATE|MAP_ANONYMOUS). *MAP_ANONYMOUS* will ensure that the mapping is not backed up by an underlying file, and the contents are initialized to zeroes. The system call returns the address of the mapped memory region. 

After getting our mapped memory region which is initialized to all zeros, we want to write our "flag.txt" string to it. This step will be reading our string from our socket file descriptor into our newly mapped memory buffer. A system call for this would be *[read()](https://man7.org/linux/man-pages/man2/read.2.html)*. The parameters and the return value of read() is as follows. 
```C 
ssize_t read(int fd, void *buf, size_t count);
``` 
So, to use read(), we have to pass the file descriptor *fd* of the our connection socket, and pass the address returned from mmap() as *buf*, and the length of *flag.txt* (8) as *count*. Assuming the server which spawns the SaaS binary also duplicates the STDIN, STDOUT and STDERR file descriptors to our socket (read [dup2()](https://man7.org/linux/man-pages/man2/dup.2.html)), we will use STDIN (0) as input from the socket as a paramter as *fd* to read(). 

We then pass our mapped address, which now contains the string "flag.txt" to open() as *pathname* (it is null-terminated since address is initialized with zeros). 

so far, our pseudo-C code for our solution will look like this.
```C 
void *address = mmap(NULL, 128, (PROT_READ|PROT_WRITE), (MAP_PRIVATE|MAP_ANONYMOUS), NULL, 0); 
read(STDIN, address, len("flag.txt")); 
int file_fd = open(address, O_RDONLY)
``` 

Now that we have opened the file and gotten a file descriptor, we will read the contents of the the file to a buffer, and write the read contents from the buffer to our socket. The first part is easy; we will use read() again with *fd* parameter as the file descriptor returned from the previous open() call, and the same buffer with a slight offset (not to write on the previously written "flag.txt" file name.). Our code will have one more line. 
```C 
int read_bytes = read(file_fd, address + 20, 128); 
``` 
Then we will write the contents read from the previous read() call and write it to our socket (STDOUT, using our previous assumption that standard file descriptors are duplicated). Here, we will use *[write()](https://man7.org/linux/man-pages/man2/write.2.html)*. 
```C
write(STDOUT, address + 20, read_bytes); 
``` 
Our final payload will look like this. 
```C 
void *address = mmap(NULL, 128, (PROT_READ|PROT_WRITE), (MAP_PRIVATE|MAP_ANONYMOUS), NULL, 0); 
read(STDIN, address, len("flag.txt")); 
int file_fd = open(address, O_RDONLY); 
int read_bytes = read(file_fd, address + 20, 128);
write(STDOUT, address + 20, read_bytes); 
``` 

Translating this C code to *syscall()* with respective syscall numbers and parameters will be like this. 
```C 
address = syscall(9, 0, 128, 3, 34, 0, 0, 0);                     //mmap() 
syscall(0, 0, address, 9, 0, 0, 0);                               //read() 
fild_fd = syscall(2, address, 0, 0, 0, 0, 0);                     //open() 
read_bytes = syscall(0, file_fd, address + 20, 128, 0, 0, 0, 0);  //read() 
syscall(1, 1, address + 20, read_bytes, 0, 0, 0, 0);              //write() 
``` 

Finally, we shall get our flag after the final system call (write())!. What's left is to implement the above C code in python using [pwntools](https://github.com/Gallopsled/pwntools) and send the appropriate parameters to *syscall()* via registers for [the SaaS](#main). 

All in all, this was a very interesting and a fun challenge about a crude implementation of a system call sandbox and how to bypass it. The SaaS binary and the solution python script can be found [here](https://github.com/RoberaHaile/ctf-solutions/tree/master/NahamCon-2020/SaaS). 




 
