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

#include"Jpcap_sub.h"

#ifndef IP_RF
#define IP_RF 0x8000
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

/** analyze ip header **/
u_short analyze_ip(jobject packet,u_char *data){
  struct ip *ip_pkt;
  jbyteArray src_addr,dst_addr;

#ifdef DEBUG
  puts("analyze ip");
#endif

  ip_pkt=(struct ip *)data;
  
  src_addr=(*jni_env)->NewByteArray(jni_env,4);
  dst_addr=(*jni_env)->NewByteArray(jni_env,4);
  (*jni_env)->SetByteArrayRegion(jni_env,src_addr,0,4,(char *)&ip_pkt->ip_src);
  (*jni_env)->SetByteArrayRegion(jni_env,dst_addr,0,4,(char *)&ip_pkt->ip_dst);

  (*jni_env)->CallVoidMethod(jni_env,packet,setIPValueMID,
			     (jbyte)4,
			     (jbyte)(ip_pkt->ip_tos>>5),
			     (jboolean)(ip_pkt->ip_tos&IPTOS_LOWDELAY),
			     (jboolean)(ip_pkt->ip_tos&IPTOS_THROUGHPUT),
			     (jboolean)(ip_pkt->ip_tos&IPTOS_RELIABILITY),
			     (jboolean)(ip_pkt->ip_off&IP_RF),
			     (jboolean)(ip_pkt->ip_off&IP_DF),
			     (jboolean)(ip_pkt->ip_off&IP_MF),
			     (jshort)(ntohs(ip_pkt->ip_off)&IP_OFFMASK),
			     (jshort)ntohs(ip_pkt->ip_len),
			     (jint)ntohs(ip_pkt->ip_id),
			     (jshort)ip_pkt->ip_ttl,
			     (jshort)ip_pkt->ip_p,
			     src_addr,dst_addr);
  DeleteLocalRef(src_addr);
  DeleteLocalRef(dst_addr);
  
  return ip_pkt->ip_hl<<2;
}

void set_ip(JNIEnv *env,jobject packet,char *pointer){
  struct ip *ip=(struct ip *)pointer;

  jbyteArray src=(*env)->CallObjectMethod(env,packet,getSourceAddressMID);
  jbyteArray dst=(*env)->CallObjectMethod(env,packet,getDestinationAddressMID);

  ip->ip_v=4;
  ip->ip_hl=IPv4HDRLEN>>2;
  ip->ip_id=htons((jshort)GetIntField(IPPacket,packet,"ident"));
  ip->ip_off=htons((jshort)((GetBooleanField(IPPacket,packet,"rsv_frag")?IP_RF:0)+
    (GetBooleanField(IPPacket,packet,"dont_frag")?IP_DF:0)+
    (GetBooleanField(IPPacket,packet,"more_frag")?IP_MF:0)+
    GetShortField(IPPacket,packet,"offset")));
  ip->ip_ttl=(u_char)GetShortField(IPPacket,packet,"hop_limit");
  ip->ip_tos=(GetByteField(IPPacket,packet,"priority")<<5)+
    (GetBooleanField(IPPacket,packet,"d_flag")?IPTOS_LOWDELAY:0)+
    (GetBooleanField(IPPacket,packet,"t_flag")?IPTOS_THROUGHPUT:0)+
    (GetBooleanField(IPPacket,packet,"r_flag")?IPTOS_RELIABILITY:0);
  (*env)->GetByteArrayRegion(env,src,0,4,(char *)&ip->ip_src);
  (*env)->GetByteArrayRegion(env,dst,0,4,(char *)&ip->ip_dst);
}
