# INDEX #

  1. [I want to be a Developer / Commiter / Contributor](#I_want_to_be_a_Developer_/_Commiter_/_Contributor.md)
  1. [Environment for Developers](#Environment_for_Developers.md)
    1. [Configuring the driver project in Visual Studio](#Configuring_the_driver_project_in_Visual_Studio.md)
    1. [Debugging and Testing Environment](#Debugging_and_Testing_Environment.md)
  1. [Coding Style](#Coding_Style.md)
    1. [Comment Code](#Comment_Code.md)
  1. [Direct Kernel Object Manipulation (DKOM)](#Direct_Kernel_Object_Manipulation_(DKOM).md)
  1. [Subversion](#Subversion.md)
  1. [Adding new modules and features](#Adding_new_modules_and_features.md)
  1. [oark book](#oark_book.md)

# I want to be a Developer / Commiter / Contributor #

If you colaborate with the project, but **you dont know if you are the Knowledge/skills** for the project, **this is not a problem**, you only need read some books (with the link to amazon, in bold the books more important for the project):

  * **[Wordware The Rootkit Arsenal May 2009](http://www.amazon.com/Rootkit-Arsenal-Escape-Evasion-Corners/dp/1598220616) <- ¡VERY IMPORTANT!**
  * **[Addison Wesley Professional Rootkits Subverting the windows Kernel Jul 2005](http://www.amazon.com/Rootkits-Subverting-Windows-Greg-Hoglund/dp/0321294319) <- ¡VERY IMPORTANT!**
  * **[Programming - Undocumented Windows NT](http://www.amazon.com/Undocumented-Windows-NT%C2%AE-Prasad-Dabak/dp/0764545698)**
  * **[Addison Wesley Advanced Windows Debugging Nov 2007](http://www.amazon.com/Advanced-Windows-Debugging-Mario-Hewardt/dp/0321374460)**
  * **[DRIVERS Windows2k Device Driver Book A Guide for Programmers](http://www.amazon.com/Windows-2000-Device-Driver-Book/dp/0130204315)**
  * **[MS Press - Programming the Windows Driver Model 2nd](http://www.amazon.com/Programming-Microsoft-Windows-Driver-Model/dp/0735618038)**
  * **[Microsoft Press Developing Drivers with the Windows Driver Foundation Apr 2007](http://www.amazon.com/Developing-Drivers-Windows-Foundation-Developer/dp/0735623740)**
  * **[O'Reilly - Windows NT File System Internals, A Developer's Guide](http://www.amazon.com/Windows-File-System-Internals-Developers/dp/1565922492)**
  * [Reversing Secrets of Reverse Engineering](http://www.amazon.com/Reversing-Secrets-Engineering-Eldad-Eilam/dp/0764574817)
  * **[Undocumented Windows 2000 Secrets - The Programmers Cookbook](http://www.amazon.com/Undocumented-Windows-2000-Secrets-Programmers/dp/0201721872)**
  * **[Windows 2000 native API reference](http://www.amazon.com/Windows-2000-Native-API-Reference/dp/1578701996)**
  * [Windows System Programming (4th Edition)](http://www.amazon.com/Windows-Programming-Addison-Wesley-Microsoft-Technology/dp/0321657748/)
  * [Wrox Professional Rootkits Mar 2007](http://www.amazon.com/Professional-Rootkits-Programmer-Ric-Vieler/dp/0470101547)
  * [Wiley The Shellcoders Handbook](http://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/0764544683)
  * **[Windows 7 Device Driver (Addison-Wesley Microsoft Technology)](http://www.amazon.com/Windows-Device-Addison-Wesley-Microsoft-Technology/dp/0321670213)**

Others necessary reads:

  * **[Avoiding driver security pitfalls by Matt Miller](http://download.microsoft.com/download/d/1/d/d1dd7745-426b-4cc3-a269-abbbe427c0ef/sys-t774_ddc08.pptx)**
  * **[Driver Development Part 1: Introduction to Drivers](http://www.codeproject.com/KB/system/driverdev.aspx)**
  * **[Driver Development Part 2: Introduction to Implementing IOCTLs](http://www.codeproject.com/KB/system/driverdev2.aspx)**
  * **[Driver Development Part 3: Introduction to driver contexts](http://www.codeproject.com/KB/system/driverdev3.aspx)**
  * **[Driver Development Part 4: Introduction to device stacks](http://www.codeproject.com/KB/system/driverdev4asp.aspx)**
  * **[Driver Development Part 5: Introduction to the Transport Device Interface](http://www.codeproject.com/KB/system/driverdev5asp.aspx)**
  * **[Driver Development Part 6: Introduction to Display Drivers](http://www.codeproject.com/KB/system/driverdev6asp.aspx)**
  * **[MemoryManagement at KernelMode](http://www.freewebs.com/four-f/)**
  * **[Handling IRPs: What Every Driver Writer Needs to Know](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/IRPs.doc)**
  * **http://www.cs.sjtu.edu.cn/~kzhu/cs490/ <-- (Windows Internals course, very interesing for the new people)**

Of course you can send questions to our mailing list (aka Google Groups) (view [Project Home page](http://code.google.com/p/oark/))

# Environment for Developers #

Here the page with the How To Compile Build: http://code.google.com/p/oark/wiki/How_To_Compile_Build

The driver is built with **WinDDK 6001.17121**, you can install this DDK with others DDKs in the system without problems.

For an easy environment you can install this tools:
  * **AnkhSVN** - Subversion Support for Visual Studio: http://ankhsvn.open.collab.net/
  * **DDKWizard + DDKBUILD.CMD** - Driver environment for Visual Studio: http://ddkwizard.assarbad.net/
  * **Visual Studio** - IDE with intellisense ...: http://msdn.microsoft.com/en-us/vstudio/default.aspx
  * **WinDDK 6001.17121** - The DDK to build the driver: there is a internal link for developers, commiters...
  * **Visual Assist X** - (Optional Tool, but very useful) provides productivity enhancements that help you read, write, navigate and refactor code with blazing speed in all Microsoft IDEs: http://www.wholetomato.com/

DDKWizard It is compatible with Visual Studio .NET, Visual Studio .NET 2003, Visual Studio 2005 and 2008 and the Express Editions of Visual C++ 2005 and 2008. The \normal" Visual C++ versions are supposed to work ne as well. Refer to section 2.5 and section 3.1 for some possible limitations depending on your Visual Studio version. Visual Studio 2005 and 2008 (and their avors) support all DDKWizard features!

PD: AnkhSVN dont works in Express Versions.

Video about the features of Visual Assist X (read this to understand the refactor feature etc..): http://www.wholetomato.com/flash/demoLg/demoLg.html

Video about the features of the DDKWizard: http://ddkwizard.assarbad.net/demo/

## Configuring the driver project in Visual Studio ##

In the subversion exist a visual studio project, but you need change:

  * **Properties** of the solution **.WXP** (right click in the solution project with extension **.WXP**, in solution explorer tab). In the option **"Configuration Properties"** click in **NMake** and add to **Include Search Path** and add the same in **Forced Includes**:
    * **X:\WinDDK\_PATH\DDK\_VERSION\inc\api**
    * **X:\WinDDK\_PATH\DDK\_VERSION\inc\ddk**
    * -
    * **WARNING:** NEVER REMOVE THE ENTRY:
      * **"..\..\common\common"** in **Include Search Path** and **Forced Includes**
    * **WARNING:** NEVER REMOVE THE ENTRY:
      * **"xcopy /y ".\obj%BUILD\_ALT\_DIR%\i386\`*`.sys" "..\..\oark\_usermode\oark\_usermode""** in **ddkpostbld.cmd** file
    * **WARNING:** NEVER REMOVE THE ENTRY:
      * **INCLUDES =..\..\common\common** in **sources** file

You need configure the **"WinDDK Paths"** in the file with extension **".vsprops"**

  * **Name="DDKBUILD\_PATH"**
  * **Value="C:\DDK\_BUILD\_PATH.CMD"** You can download the CMD from: **http://ddkwizard.assarbad.net/**, **Example: Value="C:\WINDDK\ddkbuild.cmd"**
  * **Name="WXPBASE", "WNETBASE"** etc..
  * **Value="C:\WinDDK\_PATH\DDK\_VERSION"**, you need add here the PATH of the WinDDK Path Version, you can find the version for build the driver in this wiki. **Example: Value="C:\WinDDK\6001.17121"**

Compile **ALWAYS** in **WXP Free** (UP in the Visal Studio Window, Look the DDKWIZARD Tutorial or Video)

## Configuring the user mode project in Visual Studio ##

The user mode executable have the driver inside (in a .rsrc), when the executable is running it dumps the driver to a temp file and load the driver. When you build the driver project the output with ".sys" extension is copied to the folder of user mode project. When you build the user mode project with a new driver version you need **Clean the project** after compile.

  * **WARNING:** NEVER REMOVE THE ENTRY:
    * **"..\..\common\common"** in **"Project Properties -> Configuration Properties -> C/C++ -> General -> Additional Include Directories"**

Compile **ALWAYS** in **Release mode**.

Also, you need change the Option in **"Project Properties -> Build Events -> Post-Build Event -> Command Line"**. The idea is use a command line for an easy debugging, for example with a shared folder between the real machine and the virtual machine, here an example:

  * **del /Q C:\Users\Dreg\Desktop\share**
  * **copy $(OutDir)\oark.exe C:\Users\Dreg\Desktop\share**

And after, you can create a symlink in the virtual machine to oark.exe (in the shared folder) and only for testing you need: Compile & run the oark.exe in the virtual machine.

## Debugging and Testing Environment ##

For an easy debugging and testing environment you can install this tools:
  * **VirtualKD** - allows speeding up (up to 45x) Windows kernel module debugging using VMWare and VirtualBox virtual machines: http://virtualkd.sysprogs.org/
  * **VirtualBox or VMWare** (only the versions **compatible** with **VirtualKD**) - x86 virtualization: **VirtualBox** http://www.virtualbox.org/ **VMWare** http://www.vmware.com/
  * **Debugging Tools for Windows** 32-bit Versions: http://www.microsoft.com/whdc/devtools/debugging/installx86.mspx
  * **Windows Symbol Packages** for the Windows Version of the Virtual Machines: http://www.microsoft.com/whdc/devtools/debugging/symbolpkg.mspx
  * If you like the **IDA Pro** for debugging - Kernel debugging with IDA Pro / Windbg plugin and VirtualKd: http://www.hexblog.com/?p=123

To test the user mode and the driver the best and the safe way is in a Virtual Machine, you need configure this Virtual Machine with VirtualKD for an easy-debugging (without VirtualKD kernel debugging is very very slow).

The code have some DKOM code (Direct Kernel Object Manipulation), then it is necessary hardcode some offsets of Windows Kernel structures in the code. In each Windows version have different offset for the same field of a structure. Then you need install a lot of Virtual Machines with different Windows Version: XP, Vista, 7 ...

Of course you need download the Windows Symbols for each Version to view the structs from WinDBG etc..

VirtualBox and VMWare have support for shared folders between the Virtual Machine and the Real Machine, then you can configure the output of the project in Visual Studio to the shared folder. And after, it is only necessary, compile and execute the .exe from the Virtual Machines.

# Coding Style #

All headers or source files must be with the MIT License:

```
/*
Copyright (c) <THE_YEAR> <Author, maybe an email or other info>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
```

The code must be justified to 77 columns, you can configure the Visual Assist -> Options -> Display: 77 columns

Identation always with 4 spaces (without TAB CHAR!).

Braces of functions and IF in new paragraph:

```
void Function( void )
{ 
    if ( condition )
    {
     
    }
} 
```

Params in functions and args with spaces after the comma:

```
void Function( int arg1, char arg2 )
{ 
    OtherFunction( arg1, arg2, arg3 );
} 
```

If-else, valid:

```
if ( condition )
    one_thing
else
    one_thing

if ( condition )
{
    one_or_more_thing
}
else
{
    one_or_more_thing
}

if ( condition )
    one_thing
else
{
    two_or_more_thing
}

if ( condition )
{
    two_or_more_thing
}
else
    one_thing

```

NOT VALID: an if with one thing with braces and the else with one thing without braces, it is incongruent.

The Switch with space (this is not a function), using case and breaks like a brace:

```
switch ( option )
{
    case 1:
        Function();
    break;

    default:
        other stuff....
    break;
}
```

Name of functions with the first letter of each word UPPER: Example

` WhatIsYourName() `

The ptrs always with space between the name, example:

```
char * WhatIsYourName( char ** arg1, char * arg2 )
{
   char * returnf;

   returnf = NULL;
   * arg1 = NULL;

   return returnf;
}
```

While, For, Do-while:

```
while ( 1 )
{
    for ( i = 0; i < x; i++ )
    {
    }
}

while ( 1 )
    one_thing

for ( i = 0; i < x; i++ )
    one_thing

do
{

} while ( ... );
```

Variable names in lower, separation with _, example: i\_am\_a\_variable_

#define, constants, and enums in UPPER, example: #define BLA( x ) ...

Owns typedefs in UPPER with the end _t, example:_

```
typedef enum OWN_ENUM_e
{
    BLA1 = 2,
    BLA3
} OWN_ENUM_t;
```

Example of spaces in printf and fprintf:

```
printf( "bla bla %d %d", integer, integer );
fprintf( stderr, "bla bla %d %d", integer, integer );
```

Large Functions in IF, or some large stuff:
```
if 
(
    LoooooooooooooooooooooooooooooooooooooooooooongFunction
    (
        arg1,
        arg2
    )
)
{
}

variable_name = \
    LoooooooooooooooooooooooooooooooooooooooooooongFunction \
    (
        arg1,
        arg2
    )

printf
(
    " blablabla\n"
    "ble ble ble"
    ,
    arg1,
    arg2
);

if ( condition ) 
{
    printf
        ( " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ", aa, bb );
}

if ( condition ) 
{
    printf
    ( 
        " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaffffffffffffaaaaaaaaaaaaaaa ", aa, bb 
    );
}

if ( condition ) 
{
    printf
    ( 
        " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafffffffffffffffffffffffaaaaaaaaaaaaaa ", 
        aa, bb 
    );
}
```

Please use comments if this are necessary.

GO-TO, go-to is allow but only if this is necessary like in some driver parts, in user mode if is better if you can avoid the use of goto for example:

```
BOOLEN Example( void )
{
    char * first;
    char * second;
    char * third;
    BOOLEAN returnf = FALSE;

    first = calloc( ... );
    if ( first != NULL )
    {
        second = calloc( ... );
        if ( second != NULL )
        {
            third = calloc( ... );
            if ( third != NULL )
            {
                free( third );
 
                returnf = TRUE;
            }

            free( second );
        }

        free( first );
    }

    return returnf;
}
```

Please AVOID THIS KIND OF CODE:

```
BOOLEN Example( void )
{
    char * first;
    char * second;
    char * third;
    BOOLEAN returnf = FALSE;

    first = calloc( ... );
    if ( first == NULL )
        goto first_fail
    
    second = calloc( ... );
    if ( second == NULL )
        goto second_fail

    third = calloc( ... );
    if ( third == NULL )
        goto third_fail

    returnf = TRUE;
    
    free( third );

    third_fail:
        free( second );

    second_fail:
        free( first );

    first_fail:
        return returnf;
}
```

Of course there are scenarios which GO-TO is better and more clear than other complex logic, but in examples like the last is better avoid the use of goto.


## Comment Code ##

We use Doxygen to comment code, you need install:

  * **Doxygen**: http://www.stack.nl/~dimitri/doxygen/, the binary distribution for windows have a easy Doxygen GUI.
  * **MiKTeX**: http://www.miktex.org/
  * **MinGW**: http://www.mingw.org/ (or Cygwin Make)
  * **egrep.exe & expr.exe of Cygwin** (base-system): http://www.cygwin.com/
  * **nmake** (if you have installed visual studio etc.. you dont need install this again).

You need **add to the system PATH variable** the directories **bin of the MiKTeX, MinGW,  Cygwin**. And the **VC/bin of the Visual Studio** (the nmake is here), for example: C:\Program Files\Microsoft Visual Studio 9.0\VC\bin

You need download the **Doxyfile** from **SUBVERSION** of the project in the **ROOT** of the project, then you can open it with the Doxygen GUI to generate the Latex output in the doc directory.

You need edit one entry in Doxyfile:

**OUTPUT\_DIRECTORY = ROOT\_PROJECT\_PATH/doc**

For example: OUTPUT\_DIRECTORY = C:/WinDDK/6001.17121/src/oark/doc

**Cleaning the build** in the directory doc/latex with **NMAKE**: **nmake clean**

**Building doc** in the directory doc/latex of the project with **MAKE** of **CygWing** or **MinGW-MAKE** (you need installed the egrep.exe and expr.exe, I use the make of MinGW and the other .exes of CygWin): **mingw32-make.exe pdf**

And then you can view the **PDF output** with the all documentation of the project: **doc/latex/refman.pdf**

This file is always in the **/doc folder in the subversion** to Download (but It can be not updated, is better if you can build it from your sources).

How to comment-code the code for Doxygen:

```
/**
 * @file   example_action.h
 * @Author Me (me@example.com)
 * @date   September, 2008
 * @brief  Brief description of file.
 *
 * Detailed description of file.
 */

/**
 * @name    Example API Actions
 * @brief   Example actions available.
 * @ingroup example
 *
 * This API provides certain actions as an example.
 *
 * @param [in] repeat  Number of times to do nothing.
 *
 * @retval TRUE   Successfully did nothing.
 * @retval FALSE  Oops, did something.
 *
 * Example Usage:
 * @code
 *    example_nada(3); // Do nothing 3 times.
 * @endcode
 */
boolean example(int repeat);
int var; /**< Detailed description after the member */

//! An enum.
/*! More detailed enum description. */
enum TEnum 
{ 
    TVal1, /*!< Enum value TVal1. */  
    TVal2, /*!< Enum value TVal2. */  
    TVal3  /*!< Enum value TVal3. */  
} 
```

# Direct Kernel Object Manipulation (DKOM) #

Here you have structures definitions and offsets of each field, very usefull for **XP/VISTA/7 compatibility**: http://msdn.moonsols.com/

# Subversion #

http://svnbook.red-bean.com/en/1.2/svn-book.html: This book is very interesting and it explains a lot of concepts of Control Software.

# Adding new modules and features #

Each module in OARK can have one up to 32 features (for now). Each feature is defined in the module's header file as a DWORD with **only one bit set**.

Each Definition **must** begin with:

```
#define FIN_<module short name>_<feature> value
```

For example:

```
#define FIN_SSDT_STD   (0x00000001) // Binary = 00000000 0000000 00000000 00000001
#define FIN_SSDT_XRAYN (0x00000002) // Binary = 00000000 0000000 00000000 00000010
```

Additionally, it is required that a default feature is defined. This feature must be the result of Bitwise OR-ing all the default features together.

For example:

```
#define FIN_SSDT_DEFAULTS ( FIN_SSDT_XRAYN | FIN_SSDT_STD )
```

Moreover, each module must have an "Entry point" function which accepts the following arguments:

  * FUNC\_ARGS\_t `*` flags
> (As in [revision 375](https://code.google.com/p/oark/source/detail?r=375)). A struct containing a DWORD denoting which features are enabled and which are not.
  * FUNC\_ARGS\_GLOBAL\_t `*` globals
> (As in [revision 375](https://code.google.com/p/oark/source/detail?r=375)). A struct containing global definitions.

For Example:
```
STATUS_t CheckSSDTHooking(FUNC_ARGS_t * args, FUNC_ARGS_GLOBAL_t * globals)
```

Where **flags** inside **FUNC\_ARGS\_t** is used for deciding which features should be executed or not.
Given the above example, CheckSSDTHooking function must only execute features enabled features. For example:

```
STATUS_t CheckSSDTHooking(FUNC_ARGS_t * args, FUNC_ARGS_GLOBAL_t * globals)
{
   // ...

   if ( args.flags & FIN_SSDT_STD )
   {
       // Execute feature STD
       something = SsdtShadowHookingDetection( /*some arguments*/ );
   }

   if ( args.flags & FIN_SSDT_XRAYN )
   {
      // Execute feature XRAYN
      something = CheckXraynPoc( /*some arguments*/ );
   }
   
   // ...
}
```

**Adding new modules for execution**
Adding new modules requires updating the INIT\_TABLE[.md](.md) inside **init.c**.

```
INIT_TABLE_ENTRY_t INIT_TABLE[] =
{
    { {FIN_SYSENTER_DEFAULTS}, CheckSysenterHookDetection, TRUE, "SYSENTER HOOKING DETECTION", 1 },
    { {FIN_IDT_DEFAULTS}, idt, TRUE, "IDT INFORMATION", 2 },
    { {FIN_PEBHOOKING_DEFAULTS}, CheckPEBHooking, TRUE, "PEB HOOKING DETECTION", 3 }
};
```

INIT\_TABLE\_ENTRY\_t is defined as:
```
typedef struct INIT_TABLE_ENTRY_s
{
    FUNC_ARGS_t                 function_args; // Arguments struct
    INIT_TABLE_ENTRY_FUNC_t     function; // Module's entry function
    BOOLEAN                     enable; // Module is Enabled or Disabled
    char                      * name; // Official module's name
    int				id; // Unique module's id, given by programmer

} INIT_TABLE_ENTRY_t;
```

For Example, given the SSDT module:
  * **FIN\_SSDT\_DEFAULTS** Is the default features
  * **CheckSSDTHooking** Is the entry function of this module
  * **TRUE** Yes this module is enabled by default
  * **"SSDT HOOKING DETECTion"** is the official name of this module
  * **0** is the unique id of this module, which i just came up with

Therefore the new INIT\_TABLE[.md](.md) should look like this:

```
INIT_TABLE_ENTRY_t INIT_TABLE[] =
{
    { {FIN_SSDT_DEFAULTS}, CheckSSDTHooking, TRUE, "SSDT HOOKING DETECTION", 0 },
    { {FIN_SYSENTER_DEFAULTS}, CheckSysenterHookDetection, TRUE, "SYSENTER HOOKING DETECTION", 1 },
    { {FIN_IDT_DEFAULTS}, idt, TRUE, "IDT INFORMATION", 2 },
    { {FIN_PEBHOOKING_DEFAULTS}, CheckPEBHooking, TRUE, "PEB HOOKING DETECTION", 3 }
};
```

**Define command line arguments**
Defining the command line arguments for your module in OARK is rather simple. Inside **init.c** you will find a tabled defined as **ARGUMENT\_PARSER\_TABLE\_t ARG\_TABLE[.md](.md)**.

Which contains elements of the following struct:
```
typedef struct ARGUMENT_PARSER_TABLE_s
{
	char		*	command_line_flag; // The command line argument
	char		*	command_line_description; // description of feature
	FUNC_ARGS_t		function_arg; // The feature's arguments
	int			init_table_entry_id; // The associated module's id from INIT_TABLE[]

} ARGUMENT_PARSER_TABLE_t;
```

For example, SSDT module features can be added as:

  * **"S"** Module's default features command line argument
  * **"SSDT Hook detection module with default options"** Feature description
  * **{FIN\_SSDT\_DEFAULTS}** The FUNC\_ARGS\_t struct with default flag
  * **0** SSDT Module's id as defined in INIT\_TABLE[.md](.md)

Additionally, we can define Shadow and xrayn features as "Ss" and "Sx".

The new ARG\_TABLE[.md](.md) should look like this:

```
ARGUMENT_PARSER_TABLE_t ARG_TABLE[] =
{
	{ "S", "SSDT Hook detection module with default options", {FIN_SSDT_DEFAULTS}, 0 },
	{ "Ss", "Display hooked SSDT shadow entries", {FIN_SSDT_STD}, 0 },
	{ "Sx", "Display potential hook in KTHREAD.ServiceTable field (Xrayn POC)", {FIN_SSDT_XRAYN}, 0 }
}
```

# oark book #

The oark book links:
  * View The oark book online: [click here](https://docs.google.com/viewer?a=v&pid=sites&srcid=ZGVmYXVsdGRvbWFpbnxvYXJrc3RvcmV8Z3g6M2MzNzdlYjY5ZTJkYzIzNw)
  * Download the oark book: [click here](https://sites.google.com/site/oarkstore/oarkbook.zip?attredirects=0) (ZIP file)
  * The oark book site: [click here](https://sites.google.com/site/oarkstore/)

LaTeX for Windows: **[MiKTeX 2.9](http://miktex.org/2.9/setup)**

LaTeX editors:
  * **[WinEdt 6.0](http://www.winedt.com/winedt.html)**
  * **[TeXnicCenter](http://www.texniccenter.org/)**

Make the output with WinEdt (the spelling by default is English):
  * Open the .tex oark book.
  * (Up in the window): TeX - > PDF -> PDFTeXify.

LaTeX Documentation:
  * [Getting Started with LaTeX](http://www.maths.tcd.ie/~dwilkins/LaTeXPrimer/)

The lastest output book always be: **trunk/VERSION/doc/oark book.pdf**

.tex and other Latex resources: **trunk/VERSION/doc/book latex**