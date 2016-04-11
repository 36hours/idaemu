idaemu
==============

idaemu is an IDA Pro Plugin - use for emulating code in IDA Pro. it is base on [unicorn-engine](http://www.unicorn-engine.org).  

Support architecture:
- X86 (16, 32, 64-bit) 
- ARM (developing)

Now it is not support call the library functions.

Install
-------

If you want to use idaemu, you have to install [unicorn-engine](http://www.unicorn-engine.org) and Python binding first. Then use the `idaemu.py` as the idapython script.  


License
-------

This project is released under the [GPL license](COPYING).


Example
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
