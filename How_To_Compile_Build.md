# Introduction #

**( Get the sources from the Subversion: svn checkout http://oark.googlecode.com/svn/trunk/ )**

To build/compile oark is necessary the Visual Studio (we are using the 2008 version). Build **ALWAYS** first the driver, and after the User Mode project, it needs the driver to compile:

**To build the driver** you need the **DDKWIZARD, the WINDDK (we are using WinDDK 6001.17121) and the DDKBUILDCMD:**  View this page to know how it works, installation etc.: http://code.google.com/p/oark/wiki/Developers_Guide#Environment_for_Developers

  * **oark driver**, we recommend use **WXP Free**:
    * From **Visual Studio GUI:** open the oark\_driver.sln, select if you want a WXP Free or WXP Checked, and click in Build in the top of window and after: Build Solution.
    * From **Command line:**
      1. Set variables: **set WXPBASE=C:\WinDDK\6001.17121**
      1. Build the driver (you can use -WXP checked instead -WXP free): **c:\WinDDK\ddkbuild.cmd  -WXP free "C:\oark\oark\_driver\oark\_driver"**
      1. Run the Postbuild script (this script copy the driver to user mode folder): **"C:\oark\oark\_driver\oark\_driver\ddkpostbld.cmd"**

  * **oark usermode**, we recommend use **Release**:
    * From **Visual Studio GUI:** open the oark\_usermode.sln, select if you want a Release or Debug Build, and click in Build in the top of window and after: Build Solution.
    * From **Visual Studio Command line:** Using the Visual Studio 2008 Command Prompt: **cmd.exe /k "c:\Program Files\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" x86**
      * Release: C:\oark\oark\_usermode>**msbuild /p:configuration=Release oark\_usermode.sln**
      * Debug: C:\oark\oark\_usermode>**msbuild /p:configuration=Debug oark\_usermode.sln**

After this. The **oark.exe** is in the **oark\Release** directory. The executable have inside the driver.