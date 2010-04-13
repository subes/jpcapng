# Makefile for jpcap
# Copyright (c) 2000 Keita Fujii

JAVA_DIR = /usr/local/java
#JAVA_DIR = $(JAVA_HOME)
JNI_INCLUDE = $(JAVA_DIR)/include

# Uncomment the one which includes your OS
#JNI_INCLUDE2 = $(JAVA_DIR)/include/freebsd
#JNI_INCLUDE2 = $(JAVA_DIR)/include/solaris
JNI_INCLUDE2 = $(JAVA_DIR)/include/linux

# Specify where pcap.h is
PCAP_INCLUDE = /usr/include
#PCAP_INCLUDE = /usr/include/pcap

# Use -G option for SunOS/Solaris,
# -shared option for FreeBSD/Linux
COMPILE_OPTION = -shared -L.
#COMPILE_OPTION = -G

JAVA_NATIVE_CLASSES = jpcap.JpcapSender \
		      jpcap.JpcapCaptor \
		      jpcap.JpcapWriter
#JAVA_JNI_HEADERS = $($(subst .,_,$(JAVA_NATIVE_CLASSES)):%=%.h)
JAVA_JNI_HEADERS = $(patsubst %,%.h,$(subst .,_,$(JAVA_NATIVE_CLASSES)))

#CC = cl
CC = gcc

all: libjpcap.so

libjpcap.so: Jpcap.c Jpcap_ipaddr.c JpcapSender.c JpcapWriter.c\
             packet_arp.c packet_datalink.c packet_icmp.c packet_ip.c\
             packet_ipv6.c packet_tcp.c packet_udp.c 
		$(CC) $(COMPILE_OPTION) -I$(JNI_INCLUDE) -I$(JNI_INCLUDE2)\
		 -I$(PCAP_INCLUDE)\
		Jpcap.c Jpcap_ipaddr.c JpcapSender.c JpcapWriter.c\
          packet_arp.c packet_datalink.c packet_icmp.c packet_ip.c\
          packet_ipv6.c packet_tcp.c packet_udp.c\
		-o libjpcap.so -lpcap

jniHeaders:
	echo $(JAVA_JNI_HEADERS)
	javah -classpath ../../bin -jni \
		$(JAVA_NATIVE_CLASSES)
	@echo 'Re-dosifying jni header files: $(JAVA_JNI_HEADERS)'
	@perl -pi -e 's/$$/
