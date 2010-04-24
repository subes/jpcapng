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
    JNI_INCLUDE2 = $(JAVA_DIR)/include/linux
    ifeq ($(LBITS),64)
        COMPILE_OPTION = -shared -L. -fPIC
    else
        COMPILE_OPTION = -shared -L.
    endif
    SUFFIX = .so
else
ifeq ($(PLATFORM), FreeBSD)
    JNI_INCLUDE2 = $(JAVA_DIR)/include/freebsd
    ifeq ($(LBITS),64)
        COMPILE_OPTION = -shared -L. -fPIC
    else
        COMPILE_OPTION = -shared -L.
    endif
    SUFFIX = .so
else
ifeq ($(PLATFORM), SunOS)
    JNI_INCLUDE2 = $(JAVA_DIR)/include/solaris
    COMPILE_OPTION = -G
    SUFFIX = .so
else
ifeq ($(PLATFORM), Darwin)
    JNI_INCLUDE2 = /System/Library/Frameworks/JavaVM.framework/Headers 
    COMPILE_OPTION = -bundle -framework JavaVM
    SUFFIX = .jnilib
endif
endif
endif
endif

# Specify where pcap.h is
PCAP_INCLUDE = /usr/include
#PCAP_INCLUDE = /usr/include/pcap

#CC = cl
CC = gcc

all: libjpcap.so

libjpcap.so: src/JpcapCaptor.c src/JpcapSender.c src/JpcapWriter.c\
             src/packet_arp.c src/packet_datalink.c src/packet_icmp.c src/packet_ip.c\
             src/packet_ipv6.c src/packet_tcp.c src/packet_udp.c 
		$(CC) $(COMPILE_OPTION) -I$(JNI_INCLUDE) -I$(JNI_INCLUDE2)\
		 -I$(PCAP_INCLUDE)\
		src/JpcapCaptor.c src/JpcapSender.c src/JpcapWriter.c\
          src/packet_arp.c src/packet_datalink.c src/packet_icmp.c src/packet_ip.c\
          src/packet_ipv6.c src/packet_tcp.c src/packet_udp.c\
		-o bin/libjpcap$(SUFFIX) -lpcap
clean:
		-rm bin/libjpcap$(SUFFIX)
		
$(shell mkdir -p bin)
