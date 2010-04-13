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

#ifdef INET6
#define COMPAT_RFC2292
#include<netinet/ip6.h>
#include<netinet6/ah.h>
#include<sys/socket.h>
#endif

#ifdef INET6
u_short analyze_ipv6(jobject packet,u_char *data){
  struct ip6_hdr *v6_pkt;
  jbyte proto;
  jbyteArray src_addr,dst_addr;
  int hlen=0;
  
#ifdef DEBUG
  puts("analyze ipv6");
#endif

  v6_pkt=(struct ip6_hdr *)data;
  
  src_addr=(*jni_env)->NewByteArray(jni_env,16);
  dst_addr=(*jni_env)->NewByteArray(jni_env,16);
  (*jni_env)->SetByteArrayRegion(jni_env,src_addr,0,16,
				 (char *)&v6_pkt->ip6_src);
  (*jni_env)->SetByteArrayRegion(jni_env,dst_addr,0,16,
				 (char *)&v6_pkt->ip6_dst);

  (*jni_env)->CallVoidMethod(jni_env,packet,setIPv6ValueMID,
			     (jbyte)6,
			     //class
			     (jbyte)(v6_pkt->ip6_flow&0x0ff00000)>>20,
			     (jint)ntohl(v6_pkt->ip6_flow&0x000fffff),
			     (jshort)ntohs(v6_pkt->ip6_plen),
			     (jbyte)v6_pkt->ip6_nxt,
			     (jshort)v6_pkt->ip6_hlim,
			     src_addr,
			     dst_addr);
  
  DeleteLocalRef(src_addr);
  DeleteLocalRef(dst_addr);
  
  hlen+=40;
  proto=v6_pkt->ip6_nxt;
  while(proto==IPPROTO_HOPOPTS || proto==IPPROTO_DSTOPTS ||
	proto==IPPROTO_ROUTING || proto==IPPROTO_AH ||
	proto==IPPROTO_FRAGMENT){

    jobject opt_hdr=AllocObject(IPv6Option);
    struct ip6_ext *ip6_ext=(struct ip6_ext *)data;
    struct ip6_frag *ip6_frag;
    struct ip6_rthdr0 *ip6_rthdr;
    struct newah *ah;
    jbyteArray opt_data;
    jstring *addrs;
    int i;

    (*jni_env)->CallVoidMethod(jni_env,opt_hdr,setV6OptValueMID,
			       (jbyte)proto,(jbyte)ip6_ext->ip6e_nxt,
			       (jbyte)ip6_ext->ip6e_len);

    switch(proto){
    case IPPROTO_HOPOPTS: /* Hop-by-Hop */
    case IPPROTO_DSTOPTS: /* Destionation */
      opt_data=(*jni_env)->NewByteArray(jni_env,ip6_ext->ip6e_len);
      (*jni_env)->SetByteArrayRegion(jni_env,opt_data,
				     0,ip6_ext->ip6e_len,
				     (jbyte *)(ip6_ext+2));
      (*jni_env)->CallVoidMethod(jni_env,opt_hdr,setV6OptOptionMID,
				 opt_data);
      DeleteLocalRef(opt_data);
      hlen+=ip6_ext->ip6e_len;
      break;
    case IPPROTO_ROUTING:
      ip6_rthdr=(struct ip6_rthdr0 *)ip6_ext;
      addrs=(jstring *)malloc((ip6_ext->ip6e_len>>4)*sizeof(jstring));
      for(i=0;i<ip6_ext->ip6e_len>>4;i++){
	char buf[INET6_ADDRSTRLEN];
	addrs[i]=NewString((const char *)inet_ntop(AF_INET6,
						 &ip6_rthdr->ip6r0_addr[i],
						 buf, sizeof(buf)));
      }
      (*jni_env)->CallVoidMethod(jni_env,opt_hdr,setV6OptRoutingMID,
				 (jbyte)ip6_rthdr->ip6r0_type,
				 (jbyte)ip6_rthdr->ip6r0_segleft,
				 addrs);
      for(i=0;i<ip6_ext->ip6e_len>>4;i++){
	DeleteLocalRef(addrs[i]);
      }
      free(addrs);
      hlen+=ip6_ext->ip6e_len;
      break;
    case IPPROTO_FRAGMENT:
      ip6_frag=(struct ip6_frag *)ip6_ext;
      (*jni_env)->CallVoidMethod(jni_env,opt_hdr,setV6OptFragmentMID,
				 (jshort)ntohs(ip6_frag->ip6f_offlg&
					       IP6F_OFF_MASK),
				 (jboolean)(ip6_frag->ip6f_offlg&
					    IP6F_MORE_FRAG),
				 (jint)ntohl(ip6_frag->ip6f_ident));
      hlen+=8;
      break;
    case IPPROTO_AH:
      ah=(struct newah *)ip6_ext;
      (*jni_env)->CallVoidMethod(jni_env,opt_hdr,setV6OptAHMID,
				 (jint)ntohl(ah->ah_spi),
				 (jint)ntohl(ah->ah_seq));
      opt_data=(*jni_env)->NewByteArray(jni_env,ah->ah_len);
      (*jni_env)->SetByteArrayRegion(jni_env,opt_data,
				     0,ah->ah_len,
				     (jbyte *)(ah+8));
      (*jni_env)->CallVoidMethod(jni_env,opt_hdr,setV6OptOptionMID,
				 opt_data);
      DeleteLocalRef(opt_data);
      
      hlen+=ah->ah_len;
      break;
    }

    (*jni_env)->CallVoidMethod(jni_env,packet,addIPv6OptHdrMID,opt_hdr);
    DeleteLocalRef(opt_hdr);
  }

  return hlen;
}


#endif
