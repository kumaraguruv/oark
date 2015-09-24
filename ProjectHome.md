**oark - The Open Source Anti Rootkit** aims to help ordinary computer users gain an understanding of **rootkit information, detection and indentification**.

**A rootkit** is software that **enables continued privileged access to a computer**, while actively hiding its presence from administrators by subverting standard operating system functionality or other applications. Once a rootkit is installed, it allows an attacker to mask the active intrusion and to maintain privileged access to a computer by circumventing normal authentication and authorization  mechanisms.

Although rootkits can serve a variety of ends, **they have gained notoriety primarily as malware**, **hiding applications** that appropriate **computing resources** or **steal passwords** without the knowledge of administrators and users of affected systems. Rootkits can target **firmware**, a **hypervisor**, **the kernel** or, most commonly, **user-mode** applications. From: http://www.wikipedia.org/

**The oark book** site: [click here](https://sites.google.com/site/oarkstore/)

[![](https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=TACJDTH6F6KY4&item_name=oark&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted) More information about the **destionation of donations:** http://code.google.com/p/oark/wiki/donations


**Features (more features is comming):**
  * Detects [hooks](http://en.wikipedia.org/wiki/Hooking) methods:
    * [PEB Hooking](http://phrack.org/issues.html?issue=65&id=10#article)
    * [SSDT Hooking](http://uninformed.org/index.cgi?v=8&a=2&p=10)
    * [Shadow SSDT](http://www.osronline.com/showThread.cfm?link=20626) (includes [XRAYN Method](http://hi.baidu.com/jbinghe/blog/item/49a3ac51ca3f4b11367abe8d.html))
    * [SYSENTER Hooking](http://siyobik.info/index.php?module=x86&id=313)
  * [Call Gates](http://en.wikipedia.org/wiki/Call_gate) detection in [GDT](http://en.wikipedia.org/wiki/Global_Descriptor_Table) & [LDT](http://en.wikipedia.org/wiki/Local_Descriptor_Table) (is comming)
  * [LDT Forward attack](http://vexillium.org/dl.php?call_gate_exploitation.pdf) to usermode detection (is comming)
  * Extra information in the report:
    * [IDT](http://en.wikipedia.org/wiki/Interrupt_descriptor_table) (interrupt descriptor table) information
  * More features is comming...

**Documentation:**

  * View The oark book online (frequently updated): [click here](https://docs.google.com/viewer?a=v&pid=sites&srcid=ZGVmYXVsdGRvbWFpbnxvYXJrc3RvcmV8Z3g6M2MzNzdlYjY5ZTJkYzIzNw)
  * Download the oark book (frequently updated): [click here](https://sites.google.com/site/oarkstore/oarkbook.zip?attredirects=0) (ZIP file)
  * Developers Guide: [click here](http://code.google.com/p/oark/wiki/Developers_Guide)
  * How to compile build: [click here](http://code.google.com/p/oark/wiki/How_To_Compile_Build)

<wiki:gadget url="http://google-code-feed-gadget.googlecode.com/svn/trunk/gadget.xml" up\_feeds="http://oark-blog.blogspot.com/atom.xml" width="780"  height="340" border="0" up\_showaddbutton="0"/>