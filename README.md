idaemu
==============

idaemu is an IDA Pro Plugin - use for emulating code in IDA Pro. it is base on [unicorn-engine](http://www.unicorn-engine.org).  

Support architecture:
- X86 (16, 32, 64-bit) 
- ARM 
- ARM64 (ARMv8)
- MIPS (developing)

Install
-------

If you want to use idaemu, you have to install [unicorn-engine](http://www.unicorn-engine.org) and Python binding first. Then use the `idaemu.py` as the idapython script.  


License
-------

This project is released under the [GPL license](COPYING).


Example1
-------

This is easy function for add. 
```
.text:000000000040052D                 public myadd
.text:000000000040052D myadd           proc near               ; CODE XREF: main+1Bp
.text:000000000040052D
.text:000000000040052D var_4           = dword ptr -4
.text:000000000040052D
.text:000000000040052D                 push    rbp
.text:000000000040052E                 mov     rbp, rsp
.text:0000000000400531                 mov     [rbp+var_4], edi
.text:0000000000400534                 mov     edx, cs:magic	; magic dd 64h 
.text:000000000040053A                 mov     eax, [rbp+var_4]
.text:000000000040053D                 add     eax, edx
.text:000000000040053F                 pop     rbp
.text:0000000000400540                 retn
.text:0000000000400540 myadd           endp
```

Running the idapython scritp:
``` python
from idaemu import *
a = Emu(UC_ARCH_X86, UC_MODE_64)
print a.eFunc(0x040052D, None, [7])
```

Get the function result:
```
107
```


Example2
-------

If there is a library function call inner the function, we couldn't call it directly. We should use `alt` to hook the library function first.
```
.text:0000000000400560                 public myadd
.text:0000000000400560 myadd           proc near               ; CODE XREF: main+27p
.text:0000000000400560
.text:0000000000400560 var_8           = dword ptr -8
.text:0000000000400560 var_4           = dword ptr -4
.text:0000000000400560
.text:0000000000400560                 push    rbp
.text:0000000000400561                 mov     rbp, rsp
.text:0000000000400564                 sub     rsp, 10h
.text:0000000000400568                 mov     [rbp+var_4], edi
.text:000000000040056B                 mov     [rbp+var_8], esi
.text:000000000040056E                 mov     eax, [rbp+var_8]
.text:0000000000400571                 mov     edx, [rbp+var_4]
.text:0000000000400574                 add     eax, edx
.text:0000000000400576                 mov     esi, eax
.text:0000000000400578                 mov     edi, offset format ; "a+b=%d\n"
.text:000000000040057D                 mov     eax, 0
.text:0000000000400582                 call    _printf
.text:0000000000400587                 leave
.text:0000000000400588                 retn
.text:0000000000400588 myadd           endp
```

Running the idapython scritp:
``` python
from idaemu import *

a = Emu(UC_ARCH_X86, UC_MODE_64)

def myprint(uc, out, args):
    out.append("this is hook output: %d" % args[1])
    return 0

myadd_addr = 0x00400560
printf_addr = 0x00400410 
a.alt(printf_addr, myprint, 2, False)
a.eFunc(myadd_addr, None, [1, 7])
print "---- below is the trace ----"
a.showTrace()
```

Get the result:
```
---- below is the trace ----
this is hook output: 8
```
Well Done. We can alter every function in this way.


Example3
-------

Sometimes it emulates fail with some abort:
``` 
Python>from idaemu import *
Python>a = Emu(UC_ARCH_ARM, UC_MODE_THUMB)
Python>print a.eFunc(here(), 0xbeae, [4])
#ERROR: Invalid instruction (UC_ERR_INSN_INVALID)
1048576
```

Then we can use `setTrace` and `showTrace` for debugging.

```
Python>from idaemu import *
Python>a = Emu(UC_ARCH_ARM, UC_MODE_THUMB)
Python>a.setTrace(TRACE_CODE)
Python>a.eFunc(here(), 0xbeae, [4])
#ERROR: Invalid instruction (UC_ERR_INSN_INVALID)
1048576
Python>a.showTrace()
### Trace Instruction at 0x13dc, size = 2
### Trace Instruction at 0x13de, size = 2
### Trace Instruction at 0x13e0, size = 2
......
### Trace Instruction at 0x19c6, size = 2
### Trace Instruction at 0x19c8, size = 2
### Trace Instruction at 0x19ca, size = 2
### Trace Instruction at 0xbeae, size = 2
```
So we found the abort reason (the RA is wrong)
