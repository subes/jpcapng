# Microsoft Developer Studio Project File - Name="jpcap_dll" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=jpcap_dll - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "jpcap_dll.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "jpcap_dll.mak" CFG="jpcap_dll - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "jpcap_dll - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "jpcap_dll - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "jpcap_dll - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "JPCAP_DLL_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "JPCAP_DLL_EXPORTS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386

!ELSEIF  "$(CFG)" == "jpcap_dll - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "jpcap_dll___Win32_Debug"
# PROP BASE Intermediate_Dir "jpcap_dll___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "lib"
# PROP Intermediate_Dir "lib/intermediate"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "JPCAP_DLL_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I ".\microsoft_sdk\include" /I ".\src\c" /I ".\src\c\win32\jdk\include" /I ".\src\c\win32\jdk\include\win32" /I ".\src\c\win32\WpdPack\Include" /I ".\src\c\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "JPCAP_DLL_EXPORTS" /FR"lib/" /Fp"lib/jpcap_dll.pch" /YX /Fo"lib/" /Fd"lib/" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ./microsoft_sdk/lib/IPHlpApi.Lib ./src/c/win32/WpdPack/Lib/wpcap.lib ./src/c/win32/WpdPack/Lib/Packet.lib WS2_32.LIB /nologo /dll /debug /machine:I386 /out:"lib/jpcap.dll" /pdbtype:sept

!ENDIF 

# Begin Target

# Name "jpcap_dll - Win32 Release"
# Name "jpcap_dll - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\src\c\Jpcap_ether.h
# End Source File
# Begin Source File

SOURCE=.\src\c\jpcap_JpcapCaptor.h
# End Source File
# Begin Source File

SOURCE=.\src\c\jpcap_JpcapSender.h
# End Source File
# Begin Source File

SOURCE=.\src\c\jpcap_JpcapWriter.h
# End Source File
# Begin Source File

SOURCE=.\src\c\Jpcap_sub.h
# End Source File
# Begin Source File

SOURCE=.\src\c\JpcapCaptor.c
# End Source File
# Begin Source File

SOURCE=.\src\c\JpcapSender.c
# End Source File
# Begin Source File

SOURCE=.\src\c\JpcapWriter.c
# End Source File
# Begin Source File

SOURCE=.\src\c\packet_arp.c
# End Source File
# Begin Source File

SOURCE=.\src\c\packet_datalink.c
# End Source File
# Begin Source File

SOURCE=.\src\c\packet_icmp.c
# End Source File
# Begin Source File

SOURCE=.\src\c\packet_ip.c
# End Source File
# Begin Source File

SOURCE=.\src\c\packet_ipv6.c
# End Source File
# Begin Source File

SOURCE=.\src\c\packet_tcp.c
# End Source File
# Begin Source File

SOURCE=.\src\c\packet_udp.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\src\c\win32\jdk\include\jawt.h
# End Source File
# Begin Source File

SOURCE=.\src\c\win32\jdk\include\jdwpTransport.h
# End Source File
# Begin Source File

SOURCE=.\src\c\win32\jdk\include\jni.h
# End Source File
# Begin Source File

SOURCE=.\src\c\win32\jdk\include\jvmdi.h
# End Source File
# Begin Source File

SOURCE=.\src\c\win32\jdk\include\jvmpi.h
# End Source File
# Begin Source File

SOURCE=.\src\c\win32\jdk\include\jvmti.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
