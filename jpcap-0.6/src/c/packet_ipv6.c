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

#include"Jpcap_sub.h"

#ifdef INET6
#ifndef WIN32
#define COMPAT_RFC2292
#include<netinet/ip6.h>
#include<netinet6/ah.h>
#include<sys/socket.h>
#else
typedef unsigned char  u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int   u_int32_t;
typedef int            pid_t;
#define IPPROTO_HOPOPTS        0 /* IPv6 Hop-by-Hop options */
#define IPPROTO_IPV6          41 /* IPv6 header */
#define IPPROTO_ROUTING       43 /* IPv6 Routing header */
#define IPPROTO_FRAGMENT      44 /* IPv6 fragmentation header */
#define IPPROTO_ESP           50 /* encapsulating security payload */
#define IPPROTO_AH            51 /* authentication header */
#define IPPROTO_ICMPV6        58 /* ICMPv6 */
#define IPPROTO_NONE          59 /* IPv6 no next header */
#define IPPROTO_DSTOPTS       60 /* IPv6 Destination options */
#include<ws2tcpip.h>
#include<tpipv6.h>
#include<netinet/ip6.h>
#include<netinet6/ah.h>
#endif
#endif

#ifdef INET6
u_short analyze_ipv6(JNIEnv *env,jobject packet,u_char *data){
  struct ip6_hdr *v6_pkt;
  jbyte proto;
  jbyteArray src_addr,dst_addr;
  int hlen=0;
  
#ifdef DEBUG
  puts("analyze ipv6");
#endif

	v6_pkt=(struct ip6_hdr *)data;

	src_addr=(*env)->NewByteArray(env,16);
	dst_addr=(*env)->NewByteArray(env,16);
	(*env)->SetByteArrayRegion(env,src_addr,0,16,
	                           (char *)&v6_pkt->ip6_src);
	(*env)->SetByteArrayRegion(env,dst_addr,0,16,
	                           (char *)&v6_pkt->ip6_dst);

	(*env)->CallVoidMethod(env,packet,setIPv6ValueMID,
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
	data+=hlen;

	while (proto==IPPROTO_HOPOPTS || proto==IPPROTO_DSTOPTS ||
	        proto==IPPROTO_ROUTING || proto==IPPROTO_AH ||
	        proto==IPPROTO_FRAGMENT) {

			jobject opt_hdr=AllocObject(IPv6Option);
			struct ip6_ext *ip6_ext=(struct ip6_ext *)data;
			struct ip6_frag *ip6_frag;
			struct ip6_rthdr0 *ip6_rthdr;
			struct newah *ah;
			jbyteArray opt_data;
			jstring *addr;
			int i,j,k;
			jobjectArray addrs;
			unsigned char buf[16];//define a char buf to store an ipv6 address
			unsigned char buf2[33];
			unsigned char tmp;

			(*env)->CallVoidMethod(env,opt_hdr,setV6OptValueMID,
			                       (jbyte)proto,(jbyte)ip6_ext->ip6e_nxt,
			                       (jbyte)ip6_ext->ip6e_len);

			switch (proto) {
					case IPPROTO_HOPOPTS: /* Hop-by-Hop */
					case IPPROTO_DSTOPTS: /* Destionation */
						opt_data=(*env)->NewByteArray(env,ip6_ext->ip6e_len);
						(*env)->SetByteArrayRegion(env,opt_data,0,ip6_ext->ip6e_len,
						                           (jbyte *)(ip6_ext+2));
						(*env)->CallVoidMethod(env,opt_hdr,setV6OptOptionMID,
						                       opt_data);
						DeleteLocalRef(opt_data);
						hlen+=ip6_ext->ip6e_len;

						break;

					case IPPROTO_ROUTING: // patch from Wang
						
						ip6_rthdr=(struct ip6_rthdr0 *)ip6_ext;//construct a Type0 Routing Header

						addr=(jstring *)malloc(sizeof(jstring));

						for (i=0;i<((ip6_ext->ip6e_len)-1);i++) {
								//char buf[INET6_ADDRSTRLEN];

								struct sockaddr_in6 sin6;
								sin6.sin6_addr=ip6_rthdr->ip6r0_addr[i];
								
								//  getnameinfo(&sin6,sizeof(sin6),buf,sizeof(buf),NULL,0,NI_NUMERICHOST);

								
								memcpy(buf, &sin6.sin6_addr, sizeof(struct in6_addr));//copy addr from struct to buf

								for(j = 0, k=0; j < sizeof(buf); j++, k = k+2)
								{
									tmp = buf[j] >> 4;
									if(tmp < 10)
									{
										buf2[k] = tmp + 48;
									}
									else
									{
										buf2[k]= tmp + 87;
									}
									tmp = buf[j] & 0x0f;
									if(tmp < 10)
									{
										buf2[k+1] = tmp + 48;
									}
									else
									{
										buf2[k+1]= tmp + 87;
									}
								}
								
								buf2[32] = '\0';//set the end of charstring
								
								*addr =NewString(buf2);//create a Java String with content of buf2
					
								addrs=(*env)->NewObjectArray(env,(jsize)((ip6_ext->ip6e_len)-1),String,NULL);
								(*env)->SetObjectArrayElement(env,addrs,i,*addr);

								/*
									addr[i]=NewString((const char *)inet_ntop(AF_INET6,
														 &ip6_rthdr->ip6r0_addr[i],
														 buf, sizeof(buf)));
								*/
							}

						(*env)->CallVoidMethod(env,opt_hdr,setV6OptRoutingMID,
						                       (jbyte)ip6_rthdr->ip6r0_type,
						                       (jbyte)ip6_rthdr->ip6r0_segleft,
						                       addrs);

						DeleteLocalRef(addr);
						DeleteLocalRef(addrs);
						hlen+=ip6_ext->ip6e_len;
						break;
					case IPPROTO_FRAGMENT:
						ip6_frag=(struct ip6_frag *)ip6_ext;
						(*env)->CallVoidMethod(env,opt_hdr,setV6OptFragmentMID,
						                       (jshort)ntohs(ip6_frag->ip6f_offlg&
						                                     IP6F_OFF_MASK),
						                       (jboolean)(((ip6_frag->ip6f_offlg&IP6F_MORE_FRAG)>0)?JNI_TRUE:JNI_FALSE),
						                       (jint)ntohl(ip6_frag->ip6f_ident));
						hlen+=8;
						break;
					case IPPROTO_AH:
						ah=(struct newah *)ip6_ext;
						(*env)->CallVoidMethod(env,opt_hdr,setV6OptAHMID,
						                       (jint)ntohl(ah->ah_spi),
						                       (jint)ntohl(ah->ah_seq));
						opt_data=(*env)->NewByteArray(env,ah->ah_len);
						(*env)->SetByteArrayRegion(env,opt_data,
						                           0,ah->ah_len,
						                           (jbyte *)(ah+8));
						(*env)->CallVoidMethod(env,opt_hdr,setV6OptOptionMID,
						                       opt_data);
						DeleteLocalRef(opt_data);

						hlen+=ah->ah_len;
						break;
				}

			(*env)->CallVoidMethod(env,packet,addIPv6OptHdrMID,opt_hdr);
			DeleteLocalRef(opt_hdr);
			proto = ip6_ext->ip6e_nxt;
			data+=ip6_ext->ip6e_len;
		}
	return hlen;
}


#endif
