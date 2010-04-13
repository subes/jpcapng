#include<jni.h>

#ifndef WIN32
#include<sys/param.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#include<sys/socket.h>
#else
#include<winsock.h>
#endif

#include<net/if.h>
#include<netinet/if_ether.h>

#include"Jpcap_sub.h"

/** analyze arp header **/
int analyze_arp(jobject packet,u_char *data){
  struct ether_arp *arp=(struct ether_arp *)data;
  jbyteArray sha,spa,tha,tpa;
  u_char hl,pl;

#ifdef DEBUG
  puts ("analyze arp");
#endif

  hl=arp->arp_hln;
  pl=arp->arp_pln;

  sha=(*jni_env)->NewByteArray(jni_env,hl);
  (*jni_env)->SetByteArrayRegion(jni_env,sha,0,hl,(char *)(data+sizeof(struct arphdr)));
  spa=(*jni_env)->NewByteArray(jni_env,pl);
  (*jni_env)->SetByteArrayRegion(jni_env,spa,0,pl,(char *)(data+sizeof(struct arphdr)+hl));
  tha=(*jni_env)->NewByteArray(jni_env,hl);
  (*jni_env)->SetByteArrayRegion(jni_env,tha,0,hl,(char *)(data+sizeof(struct arphdr)+hl+pl));
  tpa=(*jni_env)->NewByteArray(jni_env,pl);
  (*jni_env)->SetByteArrayRegion(jni_env,tpa,0,pl,(char *)(data+sizeof(struct arphdr)+hl+pl+hl));

  (*jni_env)->CallVoidMethod(jni_env,packet,setARPValueMID,
			     (jshort)ntohs(arp->arp_hrd),
			     (jshort)ntohs(arp->arp_pro),
			     (jshort)hl,(jshort)pl,
			     (jshort)ntohs(arp->arp_op),
			     sha,spa,tha,tpa);
  DeleteLocalRef(sha);
  DeleteLocalRef(spa);
  DeleteLocalRef(tha);
  DeleteLocalRef(tpa);

  return sizeof(struct arphdr)+hl*2+pl*2;
}
