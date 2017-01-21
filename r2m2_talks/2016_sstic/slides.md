# r2m2
## radare2 + miasm2 = love &#9829;

SSTIC2016 - @guedou

![](images/r2m2.jpg)



# Goals?

r2m2 is a radare2 plugin that aims to:

- use [radare2](https://github.com/radare/radare2) as a frontend to miasm2
  - tools, GUI, shortcuts, ...

- use [miasm2](https://github.com/radare/radare2) as a backend to radare2
  - asm/disas engine, symbolic execution, ...



# mer il es fou ?!?
![](images/m2_taytay.gif)



## Step #1 - Call Python from C
![](images/m2_embedded.png)

The [cffi](https://cffi.readthedocs.io/en/latest/overview.html#embedding) Python module produces a `.so`



![](images/m2_step1_dance.gif)



## Step #2 - Build a radare2 plugin

![](images/m2_r2plugin.png)

The r2 Wiki shows how to add a [new architecture](https://github.com/radare/radare2/wiki/Implementing-a-new-architecture)



![](images/m2_step2_dance.gif)



## Step #3 - Shake well

![](images/m2_r2m2_ad.png)

`assemble()` & `disassemble()` must be implemented



![](images/m2_step3_dance.gif)



## Step #4 - call graph

![](images/m2_r2m2_jmp.png)

Use miasm2 to *classify* opcodes according to radare2 types



![](images/m2_r2m2_graph.png)



<img src=images/m2_step4_tina.gif width=50%>



# Next steps?

1/ Convert m2 expressions to r2 esil

![](images/m2_r2m2_esil.png)



2/ Use the radare2 plugin API

See [video](https://asciinema.org/a/16ko4jd1e6kdrqkqjxeu248hm) &
[code](https://github.com/radare/radare2-bindings/blob/41d17b7e7ea4878790907f20a19392a274d204c7/libr/lang/p/test-py-asm.py)

![](images/r2_plugin_api.png)



# Code?

![](images/r2m2_quality.jpg)
