idaemu
==============

idaemu is an IDA Pro Plugin - use for emulating code in IDA Pro. it is base on [unicorn-engine](http://www.unicorn-engine.org).  

Support architecture:
- X86 (16, 32, 64-bit) 
- ARM 
- ARM64 (ARMv8)
- MIPS (developing)

Now it is not support call the library functions.

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
a.eFunc(0x040052D, 7)
```

Get the function result:
```
Euclation done. Below is the Result:
>>> function result = 107
```


Example2
-------

Sometimes it emulates fail with some abort:
``` 
Python>from idaemu import *
Python>a = Emu(UC_ARCH_ARM, UC_MODE_THUMB)
Python>a.eFunc(here(), 4)
#ERROR: Invalid instruction (UC_ERR_INSN_INVALID)
Euclation done. Below is the Result:
>>> function result = 1048576
```

Then we can use `setTrace` and `showTrace` for debugging.

```
Python>from idaemu import *
Python>a = Emu(UC_ARCH_ARM, UC_MODE_THUMB)
Python>a.setTrace(TRACE_CODE)
Python>a.eFunc(here(), 4)
#ERROR: Invalid instruction (UC_ERR_INSN_INVALID)
Euclation done. Below is the Result:
>>> function result = 1048576
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
So we found the abort reason (the default RA is wrong)
