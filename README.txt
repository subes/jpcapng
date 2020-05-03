How to compile on Windows:

- install mingw
- install mingw-make
- install winpcap
- install ant
- copy C:\MinGW\bin\mingw32-make.exe to C:\MinGW\bin\make.exe
- add C:\MinGW\bin to PATH environment variable
- add <ANT_INSTALL_DIR>\bin to PATH environment variable
- open terminal
- cd to <SVN_CHECKOUT_DIR>\trunk\jpcapng\Java and run "ant" (this compiles the java classes)
- see your jpcapng.jar in lib dir
- cd to <SVN_CHECKOUT_DIR>\trunk\jpcapng\C and run "ant" (this creates the jni-includes from the java classes and creates the dll)
- see your jpcapng.dll in lib dir

Mirror of: https://sourceforge.net/projects/jpcapng/
