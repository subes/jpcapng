#include<jni.h>
#include<pcap.h>

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
//#include<packet32.h>
#endif
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>

#include"jpcap_JpcapSender.h"
#include"Jpcap_sub.h"
//#include"Jpcap_ip.h"

#ifdef WIN32
//LPADAPTER adapters[MAX_NUMBER_OF_INSTANCE];
SOCKET sockRaw=INVALID_SOCKET;
#else
int soc_num=-1;
#endif

unsigned short in_cksum(unsigned short *addr,int len);

void set_ip(JNIEnv *env,jobject packet,char *pointer);
void set_tcp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data);
void set_udp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data);
int set_icmp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data);

jclass JpcapSender=NULL;

int getJpcapSenderID(JNIEnv *env, jobject obj){
  if(JpcapSender==NULL)
    GlobalClassRef(JpcapSender,"jpcap/JpcapSender");
  return GetIntField(JpcapSender,obj,"ID");
}


/**
Open socket for sending IP packet
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_openRawSocket(JNIEnv *env,jobject obj,jstring device){
//#ifdef WIN32
//  int id;
//  char *dev;

//  set_Java_env(env);
//  id=getJpcapSenderID(env,obj);

//  dev=(char *)(*env)->GetStringUTFChars(env,device,0);
//  adapters[id]=PacketOpenAdapter(dev);
//  (*env)->ReleaseStringUTFChars(env,device,dev);
//#else
  int on=1;
#ifdef WIN32
  WSADATA wsaData;
#endif

  set_Java_env(env);

#ifdef WIN32
  if(sockRaw!=INVALID_SOCKET){
#else
  if(soc_num>=0){
#endif
	  Throw(IOException,"Raw Socket is already opened.");
    return;
  }

#ifdef WIN32
  // Start Winsock up
  if (WSAStartup(MAKEWORD(2, 1), &wsaData) != 0) {
      Throw(IOException,"Failed to find Winsock 2.1 or better.");
      return;
  }

  sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, 0);
  if (sockRaw == INVALID_SOCKET) {
//	  printf("%d\n",WSAGetLastError());
      Throw(IOException,"Failed to create raw socket.");
      return;
  }
  setsockopt(sockRaw,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on));
#else
  if((soc_num=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0){
    Throw(IOException,"can't initialize socket");
    return;
  }
  setsockopt(soc_num,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on));
#endif

//#endif
}




/**
Send IP Packet
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_sendPacket(JNIEnv *env,jobject obj,jobject packet)
{
  char buf[MAX_PACKET_SIZE];
  struct ip *ip=(struct ip *)buf;
  jbyteArray data;
  int length;
  int ip_ver;
  int id=getJpcapSenderID(env,obj);
  struct sockaddr_in dest;

#ifdef WIN32
  //LPPACKET p=PacketAllocatePacket();
  //PacketInitPacket(p,buf,MAX_PACKET_SIZE);
#else
  if(soc_num<0){
    Throw(IOException,"socket not initialized yet");
    return;
  }
#endif

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

  //set destination address
  memset((char *)&dest,0,sizeof(dest));
  dest.sin_family=AF_INET;
  dest.sin_addr=ip->ip_src;

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

#ifdef WIN32
	if(sendto(sockRaw,buf,length,0,(struct sockaddr *)&dest,sizeof(dest))<0){
#else
	if(sendto(soc_num,buf,length,0,(struct sockaddr *)&dest,sizeof(dest))<0){
#endif
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

JNIEXPORT void JNICALL
Java_jpcap_JpcapSender_close(JNIEnv *env,jobject obj)
{
#ifdef WIN32
//  int id=getJpcapSenderID(env,obj);
//  PacketCloseAdapter(adapters[id]);
  WSACleanup();
#else
  closesocket(soc_num);
#endif
}