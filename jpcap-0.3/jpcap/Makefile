# Makefile for jpcap
# Copyright (c) 2000 Keita Fujii

JAVA_DIR = /usr/local/java
JNI_INCLUDE = $(JAVA_DIR)/include

# Uncomment the one which includes your OS
#JNI_INCLUDE2 = $(JAVA_DIR)/include/freebsd
JNI_INCLUDE2 = $(JAVA_DIR)/include/solaris
#JNI_INCLUDE2 = $(JAVA_DIR)/include/linux

# Specify where pcap.h is
PCAP_INCLUDE = /usr/include
#PCAP_INCLUDE = /usr/include/pcap

# Use -G option for SunOS/Solaris,
# -shared option for FreeBSD/Linux
#COMPILE_OPTION = -shared
COMPILE_OPTION = -G

#CC = cl
CC = gcc

all: libjpcap.so

libjpcap.so: Jpcap.c Jpcap_sub.h Jpcap_send.c Jpcap_ipaddr.c\
             packet_datalink.c packet_icmp.c packet_ip.c\
             packet_ipv6.c packet_tcp.c packet_udp.c packet_arp.c
		$(CC) $(COMPILE_OPTION) -I$(JNI_INCLUDE) -I$(JNI_INCLUDE2)\
		 -I$(PCAP_INCLUDE)\
		Jpcap.c Jpcap_send.c Jpcap_ipaddr.c\
                packet_datalink.c packet_icmp.c packet_ip.c\
                packet_ipv6.c packet_tcp.c packet_udp.c packet_arp.c\
		-o libjpcap.so -lpcap