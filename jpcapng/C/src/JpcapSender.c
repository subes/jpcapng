#include<jni.h>
#include<pcap.h>

//#define DEBUG
//#define BSD_BUG

#include<sys/types.h>
#ifndef WIN32
#include<sys/param.h>
#include<sys/socket.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#include<netdb.h>
#else
#include<winsock2.h>
#include<ws2tcpip.h>
//#include<packet32.h>
#endif
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<string.h>

#include"Jpcap_sub.h"
#include"Jpcap_ether.h"

#ifdef INET6
#include<netinet/ip6.h>
//#include<netinet6/ah.h>
#endif

#pragma export on
#include"jpcap_JpcapSender.h"
#pragma export reset

unsigned short in_cksum(unsigned short *addr,int len);
int set_packet(JNIEnv *env, jobject packet,char *pointer,int include_datalink);

int set_ether(JNIEnv *env,jobject packet,char *pointer);
void set_ip(JNIEnv *env,jobject packet,char *pointer);
void set_tcp(JNIEnv *env,jobject packet,char *pointer,jbyteArray option,jbyteArray data,struct ip *ip);
void set_udp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data,struct ip *ip);
int set_icmp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data);
int set_arp(JNIEnv *env,jobject packet,u_char *pointer);
#ifdef INET6
void set_ipv6(JNIEnv *env,jobject packet,char *pointer);
#endif

jclass JpcapSender=NULL;

int getJpcapSenderID(JNIEnv *env, jobject obj){
  if(JpcapSender==NULL)
    GlobalClassRef(JpcapSender,"jpcap/JpcapSender");
  return GetIntField(JpcapSender,obj,"ID");
}


/*
 * Class:     jpcap_JpcapSender
 * Method:    nativeOpenDevice
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT jstring JNICALL Java_jpcap_JpcapSender_nativeOpenDevice
(JNIEnv *env, jobject obj, jstring device){
	char *dev;
	jint id;
	
	set_Java_env(env);
	
	id=getJpcapSenderID(env,obj);


	jni_envs[id]=env;

	if(pcds[id]!=NULL){
		return NewString("Another Jpcap instance is being used.");
	}
	if(device==NULL){
		return NewString("Please specify device name.");
	}
	dev=(char *)GetStringChars(device);

	pcds[id]=pcap_open_live(dev,65535,0,1000,pcap_errbuf[id]);

	ReleaseStringChars(device,dev);

	if(pcds[id]==NULL) return NewString(pcap_errbuf[id]);

	return NULL;
}

/**
Send packet via pcap
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_nativeSendPacket(JNIEnv *env,jobject obj,jobject packet){
  char buf[MAX_PACKET_SIZE];
  int length;
  int id=getJpcapSenderID(env,obj);

  if(pcds[id]==NULL){
	Throw(IOException,"Another JpcapSender instance is being used.");
	return;
  }

#ifdef DEBUG
  puts("set packet.");
#endif
  length=set_packet(env,packet,buf,-1);
  if(length<60){ //include Ethernet trailer
	  memset(buf+length,0,60-length+1);
	  length=60;
  }

#ifdef DEBUG
  puts("send packet.");
#endif
  if(pcap_sendpacket(pcds[id],buf,length)<0){
		Throw(IOException,pcap_errbuf[id]);
    return;
  }
}

int set_packet(JNIEnv *env, jobject packet,char *pointer,int include_datalink){
  int length=0,dthlen=0;
  jbyteArray data=GetObjectField(Packet,packet,"[B","data");
  length=(*env)->GetArrayLength(env,data);
  int option_length = 0; //Gets properly set if its an tcppacket
  
  if(include_datalink){
	dthlen=set_ether(env,packet,pointer);
    pointer+=dthlen;
  }

  if(IsInstanceOf(packet,IPPacket)){
	struct ip *ip=(struct ip *)pointer;
#ifdef INET6
	struct ip6_hdr *ipv6=(struct ip6_hdr *)pointer;
#endif
	int ver=GetByteField(IPPacket,packet,"version");

	if(ver==4){
		set_ip(env,packet,pointer);
		///XXX: This does not consider IP options
		length+=IPv4HDRLEN;
		pointer+=IPv4HDRLEN;
	}else{
#ifdef INET6
		set_ipv6(env,packet,pointer);
		///XXX: This does not consider IP options
		length+=40;
		pointer+=40;
#else
		Throw(IOException,"only IPv4 packet is supported");
		return 0;
#endif
	}
	if(IsInstanceOf(packet,TCPPacket)){
	    jbyteArray option=GetObjectField(TCPPacket,packet,"[B","option");
	    option_length=(*env)->GetArrayLength(env,option);

		length+=TCPHDRLEN;
		if(ver==4){
			ip->ip_p=IPPROTO_TCP;
			ip->ip_len=length;
		    ip->ip_len+=option_length;
#ifdef INET6
		}else{
			ipv6->ip6_nxt=IPPROTO_TCP;
			ipv6->ip6_plen=length;
#endif
		}

		set_tcp(env,packet,pointer,option,data,ip);
	  }else if(IsInstanceOf(packet,UDPPacket)){
		length+=UDPHDRLEN;
		if(ver==4){
			ip->ip_p=IPPROTO_UDP;
			ip->ip_len=length;
#ifdef INET6
		}else{
			ipv6->ip6_nxt=IPPROTO_UDP;
			ipv6->ip6_plen=length;
#endif
		}

		set_udp(env,packet,pointer,data,ip);
	  }else if(IsInstanceOf(packet,ICMPPacket)){
		length+=set_icmp(env,packet,pointer,data);
		if(ver==4){
			ip->ip_p=IPPROTO_ICMP;
			ip->ip_len=length;
#ifdef INET6
		}else{
			ipv6->ip6_nxt=IPPROTO_ICMP;
			ipv6->ip6_plen=length;
#endif
		}
	}else{
		if(ver==4){
			ip->ip_p=(unsigned char)GetShortField(IPPacket,packet,"protocol");
			ip->ip_len=length;
			//bug fix by Brad Dillmn
			(*env)->GetByteArrayRegion(env,data,0,
					   length-IPv4HDRLEN,pointer);
#ifdef INET6
		}else{
			//ipv6->ip6_nxt=IPPROTO_ICMP; -> already done in set_ipv6()
			ipv6->ip6_plen=length;
			(*env)->GetByteArrayRegion(env,data,0,
					   length-40,pointer);
#endif
		}
	}

	  if(ver==4){
#ifndef BSD_BUG
		ip->ip_len=htons(ip->ip_len);
		ip->ip_off=htons(ip->ip_off);
#endif
		ip->ip_sum=0;
		ip->ip_sum=in_cksum((u_short *)ip,20);
	}
  }else if(IsInstanceOf(packet,ARPPacket)){
	length+=set_arp(env,packet,pointer);
  }else{ //unknown type
		(*env)->GetByteArrayRegion(env,data,0,
					   length,pointer);
  }

  return length+dthlen+option_length;
}

unsigned short in_cksum(unsigned short *data,int size){
        unsigned long sum = 0;

        while(size > 1){
                sum += *(data++);
                size -= 2;
        }

        if(size > 0) sum += (*data) & 0xff00;
        sum = (sum & 0xffff) + (sum >> 16);

        return ((~(unsigned short)((sum >> 16) + (sum & 0xffff))));
}

unsigned short in_cksum2(struct ip *ip,u_short len,unsigned short *data,int size){
        unsigned long sum = 0;
		u_short *p=(u_short *)&ip->ip_src;

		/*sum+=ip->ip_src.S_un.S_un_w.s_w1;
		sum+=ip->ip_src.S_un.S_un_w.s_w2;
		sum+=ip->ip_dst.S_un.S_un_w.s_w1;
		sum+=ip->ip_dst.S_un.S_un_w.s_w2;*/
		sum+=*(p++);
		sum+=*(p++);
		sum+=*(p++);
		sum+=*(p++);
		sum+=htons((u_short)(ip->ip_p&0x00ff));
		sum+=len;

        while(size > 1){
                sum += *(data++);
                size -= 2;
        }

		if(size > 0){
			sum += *(unsigned char *)data;
		}
        sum = (sum & 0xffff) + (sum >> 16);

        return ((~(unsigned short)((sum >> 16) + (sum & 0xffff))));
}



/**
Close Live Capture Device
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_nativeCloseDevice(JNIEnv *env,jobject obj)
{
  int id=getJpcapSenderID(env,obj);
  if(pcds[id]!=NULL) pcap_close(pcds[id]);
  pcds[id]=NULL;
}
