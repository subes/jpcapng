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
#include<netinet/udp.h>

#include"Jpcap_sub.h"

/** analyze udp header **/
void analyze_udp(jobject packet,u_char *data){
  struct udphdr *udp_pkt=(struct udphdr *)data;

#ifdef DEBUG
  puts("analze udp");
#endif

  (*jni_env)->CallVoidMethod(jni_env,packet,setUDPValueMID,
			     (jint)ntohs(udp_pkt->uh_sport),
			     (jint)ntohs(udp_pkt->uh_dport),
			     (jint)ntohs(udp_pkt->uh_ulen));

  /*if(caplen>UDPHDRLEN){
    jbyteArray dataArray=(*jni_env)->NewByteArray(jni_env,caplen-UDPHDRLEN);
    (*jni_env)->SetByteArrayRegion(jni_env,dataArray,0,
				   caplen-UDPHDRLEN,(char *)data+UDPHDRLEN);
    (*jni_env)->CallVoidMethod(jni_env,packet,setPacketDataMID,dataArray);
  }*/
}

void set_udp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data)
{
  struct udphdr *udp=(struct udphdr *)pointer;
  int length=(*env)->GetArrayLength(env,data);

  udp->uh_sport=htons((jshort)GetIntField(UDPPacket,packet,"src_port"));
  udp->uh_dport=htons((jshort)GetIntField(UDPPacket,packet,"dst_port"));
  if(length+IPv4HDRLEN+UDPHDRLEN>MAX_PACKET_SIZE)
    length=MAX_PACKET_SIZE-IPv4HDRLEN-UDPHDRLEN;
  udp->uh_ulen=htons((jshort)(length+UDPHDRLEN));
  udp->uh_sum=in_cksum((u_short *)udp,length+UDPHDRLEN);
  if(udp->uh_sum==0) udp->uh_sum=0xffff;
  (*env)->SetByteArrayRegion(env,data,0,length,
			     (u_char *)(pointer+UDPHDRLEN));
}
