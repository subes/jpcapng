#include<jni.h>
#include<pcap.h>

#ifndef WIN32
#include<sys/param.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#else
#include<winsock2.h>
#endif


#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/udp.h>

#include"Jpcap_sub.h"

/** analyze udp header **/
void analyze_udp(JNIEnv *env,jobject packet,u_char *data){
  struct udphdr *udp_pkt=(struct udphdr *)data;

#ifdef DEBUG
  puts("analze udp");
#endif

  (*env)->CallVoidMethod(env,packet,setUDPValueMID,
			     (jint)ntohs(udp_pkt->uh_sport),
			     (jint)ntohs(udp_pkt->uh_dport),
			     (jint)ntohs(udp_pkt->uh_ulen));

  /*if(caplen>UDPHDRLEN){
    jbyteArray dataArray=(*env)->NewByteArray(env,caplen-UDPHDRLEN);
    (*env)->SetByteArrayRegion(env,dataArray,0,
				   caplen-UDPHDRLEN,(char *)data+UDPHDRLEN);
    (*env)->CallVoidMethod(env,packet,setPacketDataMID,dataArray);
  }*/
}

void set_udp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data,struct ip *ip)
{
  jshortArray udpChecksum;
  u_short tmpChksum[1];

  struct udphdr *udp=(struct udphdr *)pointer;
  int length=(*env)->GetArrayLength(env,data);

  udp->uh_sport=htons((jshort)GetIntField(UDPPacket,packet,"src_port"));
  udp->uh_dport=htons((jshort)GetIntField(UDPPacket,packet,"dst_port"));
  if(length+IPv4HDRLEN+UDPHDRLEN>MAX_PACKET_SIZE)
    length=MAX_PACKET_SIZE-IPv4HDRLEN-UDPHDRLEN;

  udp->uh_ulen=htons((jshort)(length+UDPHDRLEN));
  // updated by Damien Daspit 5/15/01
  (*env)->GetByteArrayRegion(env,data,0,length,
			     (u_char *)(pointer+UDPHDRLEN));

   // !!!!!!!! updated by Gérard Stornello 27 December 2009 : able to specify UDP checksum field
  udpChecksum=(*env)->CallObjectMethod(env,packet,getUdpChecksumMID);

  // Computed checksum
  if(udpChecksum == NULL)
  {
    udp->uh_sum=0;
	udp->uh_sum=in_cksum2((void *)ip,(u_short *)udp,length+UDPHDRLEN);
    // If the checksum is null is coded 0xFFFF;
	if(udp->uh_sum==0) udp->uh_sum=0xffff;
  }
  // Forced checksum
  else
  {
    (*env)->GetShortArrayRegion(env,udpChecksum,0,1,(u_short *)tmpChksum);
    #if BYTE_ORDER == BIG_ENDIAN
      udp->uh_sum = tmpChksum[0];
    #else
      // swap nibbles
      udp->uh_sum = (((tmpChksum[0] & 0xff00) >> 8 ) | ((tmpChksum[0] & 0x00ff) << 8 ));
    #endif
  }
}
