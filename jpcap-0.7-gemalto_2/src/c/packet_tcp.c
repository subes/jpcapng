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
#include<netinet/tcp.h>

#include"Jpcap_sub.h"

/** analyze tcp header **/
u_short analyze_tcp(JNIEnv *env,jobject packet,u_char *data){
  struct tcphdr *tcp_pkt=(struct tcphdr *)data;
  u_short hdrlen;

#ifdef DEBUG
  puts("analze tcp");
#endif

  // updated by Damien Daspit 5/7/01
  (*env)->CallVoidMethod(env,packet,setTCPValueMID,
			     (jint)ntohs(tcp_pkt->th_sport),
			     (jint)ntohs(tcp_pkt->th_dport),
			     (jlong)ntohl(tcp_pkt->th_seq),
			     (jlong)ntohl(tcp_pkt->th_ack),
				 (jboolean)(((tcp_pkt->th_flags&TH_URG)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((tcp_pkt->th_flags&TH_ACK)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((tcp_pkt->th_flags&TH_PUSH)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((tcp_pkt->th_flags&TH_RST)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((tcp_pkt->th_flags&TH_SYN)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((tcp_pkt->th_flags&TH_FIN)>0)?JNI_TRUE:JNI_FALSE),
                 // !!!!!! Updated by Manu Bachimon
                 (jbyte)(tcp_pkt->th_off << 4 | tcp_pkt->th_x2),
				 (jboolean)(((tcp_pkt->th_flags&TH_RSV1)>0)?JNI_TRUE:JNI_FALSE),
				 (jboolean)(((tcp_pkt->th_flags&TH_RSV2)>0)?JNI_TRUE:JNI_FALSE),
                 // !!!!!! End of modification
			     (jint)ntohs(tcp_pkt->th_win),
                 // !!!!!! Updated by Manu Bachimon
                 (jshort)ntohs(tcp_pkt->th_sum),
                 // !!!!!! End of modification
			     (jshort)ntohs(tcp_pkt->th_urp));
  // *******************************

  hdrlen=tcp_pkt->th_off*4;

  /**
  Handle options
  **/
  if(hdrlen>TCPHDRLEN){
    jbyteArray dataArray=(*env)->NewByteArray(env,hdrlen-TCPHDRLEN);
    (*env)->SetByteArrayRegion(env,dataArray,0,hdrlen-TCPHDRLEN,data+TCPHDRLEN);
    (*env)->CallVoidMethod(env,packet,setTCPOptionMID,dataArray);
    DeleteLocalRef(dataArray);
  }

  /*if(caplen>hdrlen){
    jbyteArray dataArray=(*env)->NewByteArray(env,caplen-hdrlen);
    (*env)->SetByteArrayRegion(env,dataArray,0,
				   caplen-hdrlen,data+hdrlen);
    (*env)->CallVoidMethod(env,packet,setPacketDataMID,dataArray);
    DeleteLocalRef(dataArray);
  }else{
    (*env)->CallVoidMethod(env,packet,setPacketDataMID,
      (*env)->NewByteArray(env,0));
  }*/
  return hdrlen;
}

void set_tcp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data,void *ip)
{
  
  int optlen=0;
  jbyteArray tcpOptions;
  jshortArray tcpChecksum;
  u_short tmpChksum[1];

  struct tcphdr *tcp=(struct tcphdr *)(pointer);
  jint length=(*env)->GetArrayLength(env,data);

  tcp->th_sport=htons((jshort)GetIntField(TCPPacket,packet,"src_port"));
  tcp->th_dport=htons((jshort)GetIntField(TCPPacket,packet,"dst_port"));
  tcp->th_seq=htonl((unsigned long)GetLongField(TCPPacket,packet,"sequence"));
  tcp->th_ack=htonl((unsigned long)GetLongField(TCPPacket,packet,"ack_num"));
  tcp->th_off=5;
  // updated by Damien Daspit 5/7/01
  tcp->th_flags=(GetBooleanField(TCPPacket,packet,"rsv1")<<7)+
    (GetBooleanField(TCPPacket,packet,"rsv2")<<6)+
    (GetBooleanField(TCPPacket,packet,"urg")<<5)+
    (GetBooleanField(TCPPacket,packet,"ack")<<4)+
    (GetBooleanField(TCPPacket,packet,"psh")<<3)+
    (GetBooleanField(TCPPacket,packet,"rst")<<2)+
    (GetBooleanField(TCPPacket,packet,"syn")<<1)+
    (GetBooleanField(TCPPacket,packet,"fin"));
  // *******************************
  tcp->th_win=htons((jshort)GetIntField(TCPPacket,packet,"window"));
  tcp->th_urp=htons(GetShortField(TCPPacket,packet,"urgent_pointer"));

  // !!!!!!!! updated by Manu Bachimon 1st December 2006 : able to specify TCP option field

  // Get TCP option bytes
  tcpOptions=(*env)->CallObjectMethod(env,packet,getTcpOptionsMID);
  if(tcpOptions != NULL) {
    optlen=(*env)->GetArrayLength(env,tcpOptions);
    (*env)->GetByteArrayRegion(env,tcpOptions,0,optlen,(char *)&tcp->th_options);
  }

  // updating data offset field according to option length
  tcp->th_off+=(optlen/4);
  tcp->th_x2=0;

  if(length+IPv4HDRLEN+TCPHDRLEN>MAX_PACKET_SIZE)
    length=MAX_PACKET_SIZE-IPv4HDRLEN-TCPHDRLEN-optlen;
  
  // updated by Damien Daspit 5/15/01
  (*env)->GetByteArrayRegion(env,data,0,
			     length,
			     (u_char *)(pointer+TCPHDRLEN+optlen));

  
   tcp->th_sum=0;
   // !!!!!!!! updated by Manu Bachimon 1st December 2006 : able to specify TCP checksum field
   tcpChecksum=(*env)->CallObjectMethod(env,packet,getTcpChecksumMID);
   if(tcpChecksum == NULL)
   {
		tcp->th_sum=in_cksum2(ip, (u_short *)tcp, length+TCPHDRLEN+optlen );
   }
   else
   {		
      (*env)->GetShortArrayRegion(env,tcpChecksum,0,1,(u_short *)tmpChksum);
      tcp->th_sum = htons(tmpChksum[0]);
   }

  // !!!!!!!! End of modifications done by Manu Bachimon

}
