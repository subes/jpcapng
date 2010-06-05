# Makefile for jpcap
# Copyright (c) 2000 Keita Fujii
#				2010 Edwin Stang

# You should set JAVA_HOME before running 'make'
# Or, you can manually change the following line, e.g., 'JAVA_DIR = /usr/java/latest'

ifdef JAVA_HOME
	JAVA_DIR = $(JAVA_HOME)
else
	JAVA_DIR = "/usr/lib/jvm/default-java/"
endif

JNI_INCLUDE = $(JAVA_DIR)/include

# try to detect your OS using 'uname'
PLATFORM = $(shell "uname")
LBITS := $(shell getconf LONG_BIT)

ifeq ($(PLATFORM), Linux)
    PCAP_INCLUDE = /usr/include
    JNI_INCLUDE2 = $(JNI_INCLUDE)/linux
    ifeq ($(LBITS),64)
        COMPILE_OPTION = -shared -L. -fPIC
    else
        COMPILE_OPTION = -shared -L.
    endif
    PREFIX = lib
    SUFFIX = .so
    LD_LIBS = -lpcap
else
ifeq ($(PLATFORM), FreeBSD)
    PCAP_INCLUDE = /usr/include
    JNI_INCLUDE2 = $(JAVA_DIR)/include/freebsd
    ifeq ($(LBITS),64)
        COMPILE_OPTION = -shared -L. -fPIC
    else
        COMPILE_OPTION = -shared -L.
    endif
    PREFIX = lib
    SUFFIX = .so
    LD_LIBS = -lpcap
else
ifeq ($(PLATFORM), SunOS)
    PCAP_INCLUDE = /usr/include
    JNI_INCLUDE2 = $(JAVA_DIR)/include/solaris
    COMPILE_OPTION = -G
    PREFIX = lib
    SUFFIX = .so
    LD_LIBS = -lpcap
else
ifeq ($(PLATFORM), Darwin)
    PCAP_INCLUDE = /usr/include
    JNI_INCLUDE2 = /System/Library/Frameworks/JavaVM.framework/Headers 
    ifeq ($(LBITS),64)
        COMPILE_OPTION = -arch x86_64 -bundle -framework JavaVM 
    else
        COMPILE_OPTION = -bundle -framework JavaVM
    endif
    PREFIX = lib
    SUFFIX = .jnilib
    LD_LIBS = -lpcap
else
    #windows
    PCAP_INCLUDE = ./win32/include
    JNI_INCLUDE2 = $(JNI_INCLUDE)/win32
    COMPILE_OPTION = -shared -L.
    WIN32_LIB_DIRS = -L./win32/lib "-L$(LIB)"
    SUFFIX = .dll
    LD_LIBS = -lwpcap -lpacket -lWs2_32 -liphlpapi
endif
endif
endif
endif

#CC = cl
CC = gcc

all: src/JpcapCaptor.c src/JpcapSender.c src/JpcapWriter.c\
             src/packet/packet_arp.c src/packet/packet_datalink.c src/packet/packet_icmp.c src/packet/packet_ip.c\
             src/packet/packet_ipv6.c src/packet/packet_tcp.c src/packet/packet_udp.c 
		$(CC) $(COMPILE_OPTION) -I"$(JNI_INCLUDE)" -I"$(JNI_INCLUDE2)"\
		 -I"$(PCAP_INCLUDE)" $(WIN32_LIB_DIRS)\
		src/JpcapCaptor.c src/JpcapSender.c src/JpcapWriter.c\
          src/packet/packet_arp.c src/packet/packet_datalink.c src/packet/packet_icmp.c src/packet/packet_ip.c\
          src/packet/packet_ipv6.c src/packet/packet_tcp.c src/packet/packet_udp.c\
		-o bin/$(PREFIX)jpcap$(SUFFIX) $(LD_LIBS)
clean:
		-rm bin/$(PREFIX)jpcap$(SUFFIX)
		
$(shell mkdir bin)
