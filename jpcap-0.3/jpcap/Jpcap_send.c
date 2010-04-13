#include<jni.h>

#define BSD_BUG

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
#endif
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>

#include"Jpcap_sub.h"
#include"Jpcap_ip.h"


int soc_num=-1;
struct sockaddr_in sockaddr;

unsigned short in_cksum(unsigned short *addr,int len);

void set_ip(JNIEnv *env,jobject packet,char *pointer);
void set_tcp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data);
void set_udp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data);
int set_icmp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data);

/**
Open socket for sending IP packet
**/
JNIEXPORT void JNICALL
Java_jpcap_Jpcap_openRawSocket(JNIEnv *env,jobject obj){
  struct hostent *thishost;
  char buf[255];
  int on=1;

  if(soc_num>=0){
    /*socket already opened*/
    return;
  }

  /* get localhost info */
  gethostname(buf,sizeof(buf));
  if((thishost=gethostbyname((const char *)buf))==NULL){
    Throw(IOException,"can't get localhost info.");
    return;
  }

  memset((char *)&sockaddr,0,sizeof(sockaddr));
  sockaddr.sin_family=AF_INET;
  sockaddr.sin_port=12345;
  memcpy(thishost->h_addr,(char *)&sockaddr.sin_addr,thishost->h_length);

  if((soc_num=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0){
    Throw(IOException,"can't initialize socket");
    return;
  }

  setsockopt(soc_num,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on));
}




/**
Send IP Packet
**/
JNIEXPORT void JNICALL
Java_jpcap_Jpcap_sendPacket(JNIEnv *env,jobject obj,jobject packet)
{
  char buf[MAX_PACKET_SIZE];
  struct ip *ip=(struct ip *)buf;
  jbyteArray data;
  int length;
  int ip_ver;

  puts("send");
  if(soc_num<0){
    Throw(IOException,"socket not initialized yet");
    return;
  }

  data=GetObjectField(Packet,packet,"[B","data");
  if(data==NULL){
	  Throw(IOException,"Packet.data is null.");
	  return;
  }
  length=(*env)->GetArrayLength(env,data);

  if(!IsInstanceOf(packet,IPPacket)){
    Throw(IOException,"not IPPacket object");
    return;
  }
  ip_ver=GetByteField(IPPacket,packet,"version");
  if(ip_ver!=4){
    Throw(IOException,"only IPv4 packet is supported");
    return;
  }

  set_ip(env,packet,buf);
  length+=IPv4HDRLEN;

  if(IsInstanceOf(packet,TCPPacket)){
    length+=TCPHDRLEN;
    ip->ip_p=IPPROTO_TCP;
    ip->ip_len=length;

    set_tcp(env,packet,(char *)(buf+IPv4HDRLEN),data);
  }else if(IsInstanceOf(packet,UDPPacket)){
    length+=UDPHDRLEN;
    ip->ip_p=IPPROTO_UDP;
    ip->ip_len=length;

    set_udp(env,packet,(char *)(buf+IPv4HDRLEN),data);
  }else if(IsInstanceOf(packet,ICMPPacket)){
    ip->ip_p=IPPROTO_ICMP;
    ip->ip_len=length+set_icmp(env,packet,(char *)(buf+IPv4HDRLEN),data);
  }else{
    ip->ip_p=(unsigned char)GetShortField(IPPacket,packet,"protocol");
    ip->ip_len=length;
    (*env)->SetByteArrayRegion(env,data,0,length-IPv4HDRLEN,
			       (char *)ip+IPv4HDRLEN);
  }

  ip->ip_sum=0;
  ip->ip_sum=in_cksum((u_short *)ip,20);

#ifndef BSD_BUG
	ip->ip_len=htons(ip->ip_len);
	ip->ip_off=htons(ip->ip_off);
#endif

  if(sendto(soc_num,buf,length,0,(struct sockaddr *)&sockaddr,
	    sizeof(sockaddr))<0){
    Throw(IOException,"sendto error");
    return;
  }
}

unsigned short in_cksum(unsigned short *addr,int len){
     int  nleft=len;
     int  sum  =0;
     unsigned short *w =addr;
     unsigned short answer=0;
  
     while(nleft >1){
       sum += *w++;
       nleft -= 2;
     }
     if(nleft ==1){
        *(unsigned char *) (&answer) = *(unsigned char *)w;
        sum += answer;
     }
     sum =(sum >>16) +(sum & 0xffff);
     sum +=(sum >>16);
     answer =~sum;
     return(answer);  

}
