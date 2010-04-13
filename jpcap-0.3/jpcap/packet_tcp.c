#include<jni.h>

#ifndef WIN32
#include<sys/param.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#else
#include<winsock.h>
#endif

#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>

#include"Jpcap_sub.h"

/** analyze tcp header **/
u_short analyze_tcp(jobject packet,u_char *data){
  struct tcphdr *tcp_pkt=(struct tcphdr *)data;
  u_short hdrlen;
  
#ifdef DEBUG
  puts("analze tcp");
#endif

  (*jni_env)->CallVoidMethod(jni_env,packet,setTCPValueMID,
			     (jint)ntohs(tcp_pkt->th_sport),
			     (jint)ntohs(tcp_pkt->th_dport),
			     (jlong)ntohl(tcp_pkt->th_seq),
			     (jlong)ntohl(tcp_pkt->th_ack),
			     (jboolean)(tcp_pkt->th_flags&TH_URG),
			     (jboolean)(tcp_pkt->th_flags&TH_ACK),
			     (jboolean)(tcp_pkt->th_flags&TH_PUSH),
			     (jboolean)(tcp_pkt->th_flags&TH_RST),
			     (jboolean)(tcp_pkt->th_flags&TH_SYN),
			     (jboolean)(tcp_pkt->th_flags&TH_FIN),
			     (jint)ntohs(tcp_pkt->th_win),
			     (jshort)ntohs(tcp_pkt->th_urp));

  hdrlen=tcp_pkt->th_off*4;

  /**
  Handle options
  **/
  if(hdrlen>TCPHDRLEN){
    jbyteArray dataArray=(*jni_env)->NewByteArray(jni_env,hdrlen-TCPHDRLEN);
    (*jni_env)->SetByteArrayRegion(jni_env,dataArray,0,hdrlen-TCPHDRLEN,data+TCPHDRLEN);
    (*jni_env)->CallVoidMethod(jni_env,packet,setTCPOptionMID,dataArray);
    DeleteLocalRef(dataArray);
  }

  /*if(caplen>hdrlen){
    jbyteArray dataArray=(*jni_env)->NewByteArray(jni_env,caplen-hdrlen);
    (*jni_env)->SetByteArrayRegion(jni_env,dataArray,0,
				   caplen-hdrlen,data+hdrlen);
    (*jni_env)->CallVoidMethod(jni_env,packet,setPacketDataMID,dataArray);
    DeleteLocalRef(dataArray);
  }else{
    (*jni_env)->CallVoidMethod(jni_env,packet,setPacketDataMID,
      (*jni_env)->NewByteArray(jni_env,0));
  }*/
  return hdrlen;
}

void set_tcp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data)
{
  struct tcphdr *tcp=(struct tcphdr *)(pointer);
  int length=(*env)->GetArrayLength(env,data);

  tcp->th_sport=htons((jshort)GetIntField(TCPPacket,packet,"src_port"));
  tcp->th_dport=htons((jshort)GetIntField(TCPPacket,packet,"dst_port"));
  tcp->th_seq=htonl((unsigned long)GetLongField(TCPPacket,packet,"sequence"));
  tcp->th_ack=htonl((unsigned long)GetLongField(TCPPacket,packet,"ack_num"));
  tcp->th_off=5;
  tcp->th_flags=(GetBooleanField(TCPPacket,packet,"urg")<<5)+
    (GetBooleanField(TCPPacket,packet,"ack")<<4)+
    (GetBooleanField(TCPPacket,packet,"psh")<<3)+
    (GetBooleanField(TCPPacket,packet,"rst")<<2)+
    (GetBooleanField(TCPPacket,packet,"syn")<<1)+
    (GetBooleanField(TCPPacket,packet,"fin"));
  tcp->th_win=htons((jshort)GetIntField(TCPPacket,packet,"window"));
  tcp->th_urp=htons(GetShortField(TCPPacket,packet,"urgent_pointer"));
  if(length+IPv4HDRLEN+TCPHDRLEN>MAX_PACKET_SIZE)
    length=MAX_PACKET_SIZE-IPv4HDRLEN-TCPHDRLEN;
  (*env)->SetByteArrayRegion(env,data,0,
			     length,
			     (u_char *)(pointer+TCPHDRLEN));
}
