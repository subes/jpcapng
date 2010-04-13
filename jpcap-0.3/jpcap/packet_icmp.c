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
#include<netinet/ip_icmp.h>

#include"Jpcap_sub.h"

u_short analyze_ip(jobject packet,u_char *data);

/** analyze icmp header **/
void analyze_icmp(jobject packet,u_char *data,u_short clen){
  struct icmp *icmp_pkt=(struct icmp *)data;
  jobject ippacket;
  jbyteArray addr;

#ifdef DEBUG
  puts("analyze icmp");
  printf("type:%d,code:%d\n",icmp_pkt->icmp_type,icmp_pkt->icmp_code);
#endif

  (*jni_env)->CallVoidMethod(jni_env,packet,setICMPValueMID,
			     icmp_pkt->icmp_type,icmp_pkt->icmp_code,
			     icmp_pkt->icmp_cksum);
  
  if(icmp_pkt->icmp_type==0 || icmp_pkt->icmp_type==8 ||
     icmp_pkt->icmp_type>12){
    (*jni_env)->CallVoidMethod(jni_env,packet,setICMPIDMID,
			       (jint)icmp_pkt->icmp_id,
			       (jint)icmp_pkt->icmp_seq);
  }
  switch(icmp_pkt->icmp_type){
  case 5: /* redirect */
    addr=(*jni_env)->NewByteArray(jni_env,4);
    (*jni_env)->SetByteArrayRegion(jni_env,addr,0,4,
				   (char *)&icmp_pkt->icmp_gwaddr);
    (*jni_env)->CallVoidMethod(jni_env,packet,setICMPRedirectIPMID,
			       addr);
    DeleteLocalRef(addr);
  case 3: /* unreachable */
  case 4: /* source quench */
  case 11: /* time exceeded */
  case 12: /*parameter problem */
    if(clen<IPv4HDRLEN+16) break;
    ippacket=AllocObject(IPPacket);
    analyze_ip(ippacket,(u_char *)&icmp_pkt->icmp_ip);
    (*jni_env)->SetObjectField(jni_env,packet,
			    (*jni_env)->GetFieldID(jni_env,ICMPPacket,
						   "ippacket",
						   "Ljpcap/IPPacket;"),
			    ippacket);
    DeleteLocalRef(ippacket);
    break;
#ifdef icmp_num_addrs
  case 9: /* router advertisement */
    {
      jint prefs[icmp_pkt->icmp_num_addrs];
      jobjectArray addrArray=(*jni_env)->NewObjectArray(jni_env,
				(jsize)icmp_pkt->icmp_num_addrs,
							String,NULL);
      jintArray prefArray=(*jni_env)->NewIntArray(jni_env,
					      icmp_pkt->icmp_num_addrs);
      int i;
      
      for(i=0;i<icmp_pkt->icmp_num_addrs;i++){
	jstring addr_str=NewString((const char *)
	     inet_ntoa(*(struct in_addr *)(icmp_pkt->icmp_data+8+(i<<3))));
	prefs[i]=(int)(icmp_pkt->icmp_data+8+(i<<3)+4);
	(*jni_env)->SetObjectArrayElement(jni_env,addrArray,i,addr);
	DeleteLocalRef(addr_str);
      }
      (*jni_env)->SetIntArrayRegion(jni_env,prefArray,0,
				    (jsize)icmp_pkt->icmp_num_addrs,prefs);

      (*jni_env)->CallVoidMethod(jni_env,packet,setICMPRouterAdMID,
				 (jbyte)icmp_pkt->icmp_num_addrs,
				 (jbyte)icmp_pkt->icmp_wpa,
				 (jshort)icmp_pkt->icmp_lifetime,
				 addrArray,prefArray);

      DeleteLocalRef(addrArray);
      DeleteLocalRef(prefArray);
    }
    break;
#endif
  case 13: case 14: /* timestamp*/
    (*jni_env)->CallVoidMethod(jni_env,packet,setICMPTimestampMID,
			       (jlong)icmp_pkt->icmp_otime,
			       (jlong)icmp_pkt->icmp_rtime,
			       (jlong)icmp_pkt->icmp_ttime);
    break;
  case 17: case 18:   /* netmask*/
    (*jni_env)->SetIntField(jni_env,packet,
			    (*jni_env)->GetFieldID(jni_env,ICMPPacket,
						   "subnetmask","I"),
			    (jint)icmp_pkt->icmp_mask);
    break;
  }
}

int set_icmp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data)
{
  /* support only Echo request/reply */
  struct icmp *icmp=(struct icmp *)pointer;

  icmp->icmp_type=GetByteField(ICMPPacket,packet,"type");
  icmp->icmp_code=GetByteField(ICMPPacket,packet,"code");
  
  switch(icmp->icmp_type){
  case 0: /* Echo reply */
  case 8: /* Echo requect */
    icmp->icmp_id=htons((jshort)GetIntField(ICMPPacket,packet,"id"));
    icmp->icmp_seq=htons((jshort)GetIntField(ICMPPacket,packet,"seq"));
    (*env)->SetByteArrayRegion(env,data,0,
			       (*env)->GetArrayLength(env,data),
			       (u_char *)icmp->icmp_data);
    return 8;
    break;
  default:
	return 0;
  }
}
