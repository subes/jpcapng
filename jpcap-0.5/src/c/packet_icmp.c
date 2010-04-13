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
#include<netinet/ip_icmp.h>

#include"Jpcap_sub.h"

u_short analyze_ip(JNIEnv *env,jobject packet,u_char *data);

/** analyze icmp header **/
void analyze_icmp(JNIEnv *env,jobject packet,u_char *data,u_short clen){
  struct icmp *icmp_pkt=(struct icmp *)data;
  jobject ippacket;
  jbyteArray addr;

#ifdef DEBUG
  puts("analyze icmp");
  printf("type:%d,code:%d\n",icmp_pkt->icmp_type,icmp_pkt->icmp_code);
#endif

  (*env)->CallVoidMethod(env,packet,setICMPValueMID,
			     icmp_pkt->icmp_type,icmp_pkt->icmp_code,
			     icmp_pkt->icmp_cksum);
  
  if(icmp_pkt->icmp_type==0 || icmp_pkt->icmp_type==8 ||
     icmp_pkt->icmp_type>12){
    (*env)->CallVoidMethod(env,packet,setICMPIDMID,
			       (jint)icmp_pkt->icmp_id,
			       (jint)icmp_pkt->icmp_seq);
  }
  switch(icmp_pkt->icmp_type){
  case 5: /* redirect */
    addr=(*env)->NewByteArray(env,4);
    (*env)->SetByteArrayRegion(env,addr,0,4,
				   (char *)&icmp_pkt->icmp_gwaddr);
    (*env)->CallVoidMethod(env,packet,setICMPRedirectIPMID,
			       addr);
    DeleteLocalRef(addr);
  case 3: /* unreachable */
  case 4: /* source quench */
  case 11: /* time exceeded */
  case 12: /*parameter problem */
    if(clen<IPv4HDRLEN+16) break;
    ippacket=AllocObject(IPPacket);
    analyze_ip(env,ippacket,(u_char *)&icmp_pkt->icmp_ip);
    (*env)->SetObjectField(env,packet,
			    (*env)->GetFieldID(env,ICMPPacket,
						   "ippacket",
						   "Ljpcap/packet/IPPacket;"),
			    ippacket);
    DeleteLocalRef(ippacket);
    break;
#ifdef icmp_num_addrs
  case 9: /* router advertisement */
    {
      jint prefs[icmp_pkt->icmp_num_addrs];
      jobjectArray addrArray=(*env)->NewObjectArray(env,
				(jsize)icmp_pkt->icmp_num_addrs,
							String,NULL);
      jintArray prefArray=(*env)->NewIntArray(env,
					      icmp_pkt->icmp_num_addrs);
      int i;
      
      for(i=0;i<icmp_pkt->icmp_num_addrs;i++){
	jstring addr_str=NewString((const char *)
	     inet_ntoa(*(struct in_addr *)(icmp_pkt->icmp_data+8+(i<<3))));
	prefs[i]=(int)(icmp_pkt->icmp_data+8+(i<<3)+4);
	(*env)->SetObjectArrayElement(env,addrArray,i,addr);
	DeleteLocalRef(addr_str);
      }
      (*env)->SetIntArrayRegion(env,prefArray,0,
				    (jsize)icmp_pkt->icmp_num_addrs,prefs);

      (*env)->CallVoidMethod(env,packet,setICMPRouterAdMID,
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
    (*env)->CallVoidMethod(env,packet,setICMPTimestampMID,
			       (jlong)icmp_pkt->icmp_otime,
			       (jlong)icmp_pkt->icmp_rtime,
			       (jlong)icmp_pkt->icmp_ttime);
    break;
  case 17: case 18:   /* netmask*/
    (*env)->SetIntField(env,packet,
			    (*env)->GetFieldID(env,ICMPPacket,
						   "subnetmask","I"),
			    (jint)icmp_pkt->icmp_mask);
    break;
  }
}

int set_icmp(JNIEnv *env,jobject packet,char *pointer,jbyteArray data)
{
  /* support only Echo request/reply */
  struct icmp *icmp=(struct icmp *)pointer;
  jint length=0;
  
  if(data!=NULL)
	  length=(*env)->GetArrayLength(env,data);

  icmp->icmp_type=GetByteField(ICMPPacket,packet,"type");
  icmp->icmp_code=GetByteField(ICMPPacket,packet,"code");
  
  switch(icmp->icmp_type){
  case 0: /* Echo reply */
  case 8: /* Echo requect */
    icmp->icmp_id=htons((jshort)GetIntField(ICMPPacket,packet,"id"));
    icmp->icmp_seq=htons((jshort)GetIntField(ICMPPacket,packet,"seq"));
 	// updated by Damien Daspit 5/15/01
	if(data!=NULL)
		(*env)->GetByteArrayRegion(env,data,0,length,(u_char *)icmp->icmp_data);
	icmp->icmp_cksum=0;
	icmp->icmp_cksum=in_cksum((u_short *)icmp,8+length);
    return 8;
    break;
  default:
	return 0;
  }
}
