#ifdef WIN32
#include<winsock2.h>
#endif /* for WIN32 */

#include<jni.h>
#include<pcap.h>

//#include<net/bpf.h>

#ifndef WIN32
#include<sys/param.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<errno.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#ifndef SIOCGIFCONF
#include<sys/sockio.h>
#endif
#endif

#include<netinet/in_systm.h>
#include<netinet/ip.h>

#ifdef INET6
#ifndef WIN32
#define COMPAT_RFC2292
#include<netinet/ip6.h>
#include<netinet6/ah.h>
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

#include"jpcap_Jpcap.h"
#include"jpcap_IPAddress.h"

#include"Jpcap_sub.h"
#include"Jpcap_ether.h"


const int offset_type[]={0,12,-1,-1,-1,-1,20,-1,-1,2,
#ifdef PCAP_FDDIPAD
			  19+PCAP_FDDIPAD,
#else
			  19,
#endif
			  6,-1,-1,5};

const int offset_data[]={4,14,-1,-1,-1,-1,22,-1,16,4,
#ifdef PCAP_FDDIPAD
			   21+PCAP_FDDIPAD,
#else
			   21,
#endif
			   8,0,24,24};

#define get_network_type(data,id) ntohs(*(u_short *)(data+offset_type[linktypes[id]]))

#define skip_datalink_header(data,id)  (data+offset_data[linktypes[id]])

#define datalink_hlen(id) offset_data[linktypes[id]]

jclass Jpcap=NULL,JpcapHandler,Packet,DatalinkPacket,EthernetPacket,IPPacket,TCPPacket,UDPPacket,ICMPPacket,IPv6Option,ARPPacket,String,Thread,UnknownHostException,IOException;
jmethodID handleMID,setPacketValueMID,setDatalinkPacketMID,
  setPacketHeaderMID,setPacketDataMID,
  setEthernetValueMID,setIPValueMID,setIPv4OptionMID,setIPv6ValueMID,addIPv6OptHdrMID,
  setTCPValueMID,setTCPOptionMID,setUDPValueMID,
  setICMPValueMID,setICMPIDMID,setICMPTimestampMID,setICMPRedirectIPMID,
  setICMPRouterAdMID,setV6OptValueMID,setV6OptOptionMID,setV6OptFragmentMID,
  setV6OptRoutingMID,setV6OptAHMID,
  setARPValueMID,
  getSourceAddressMID,getDestinationAddressMID;
jfieldID jpcapID;

pcap_t *pcds[MAX_NUMBER_OF_INSTANCE];
int linktypes[MAX_NUMBER_OF_INSTANCE];
bpf_u_int32 netnums[MAX_NUMBER_OF_INSTANCE],netmasks[MAX_NUMBER_OF_INSTANCE];
jobject jpcap_handlers[MAX_NUMBER_OF_INSTANCE];
JNIEnv *jni_envs[MAX_NUMBER_OF_INSTANCE];

static char pcap_errbuf[PCAP_ERRBUF_SIZE];
static char buffer[256];
static char tmp_buffer[256];

void set_info(JNIEnv *env,jobject obj,pcap_t *pcd);
void set_Java_env(JNIEnv *);
void get_packet(struct pcap_pkthdr,u_char *,jobject *,int);
void dispatcher_handler(u_char *,const struct pcap_pkthdr *,const u_char *);

struct ip_packet *getIP(char *payload);

u_short analyze_ip(JNIEnv *env,jobject packet,u_char *data);
u_short analyze_tcp(JNIEnv *env,jobject packet,u_char *data);
void analyze_udp(JNIEnv *env,jobject packet,u_char *data);
void analyze_icmp(JNIEnv *env,jobject packet,u_char *data,u_short len);
#ifdef INET6
u_short analyze_ipv6(JNIEnv *env,jobject packet,u_char *data);
#endif
int analyze_arp(JNIEnv *env,jobject packet,u_char *data);
jobject analyze_datalink(JNIEnv *env,u_char *data,int linktype);


int getJpcapID(JNIEnv *env,jobject obj)
{
	return GetIntField(Jpcap,obj,"ID");
}


/**
Open Device for Live Capture
**/
JNIEXPORT jstring JNICALL
Java_jpcap_Jpcap_nativeOpenLive(JNIEnv *env,jobject obj,jstring device,jint snaplen,
			  jint promisc,jint to_ms)
{
  char *dev;
  jint id;

  set_Java_env(env);

  id=getJpcapID(env,obj);

  jni_envs[id]=env;

  if(pcds[id]!=NULL){
	return (*env)->NewStringUTF(env,"Another Jpcap instance is being used.");
  }

  if(device==NULL){
    return (*env)->NewStringUTF(env,"Please specify device name.");
  }
  dev=(char *)(*env)->GetStringUTFChars(env,device,0);

  pcds[id]=pcap_open_live(dev,snaplen,promisc,to_ms,pcap_errbuf);
  if(pcap_lookupnet(dev,&netnums[id],&netmasks[id],pcap_errbuf)==-1){
    sprintf(pcap_errbuf,"Unable to obtain  the net number or the netmask of device %s",dev);
	pcds[id]=NULL;
  }

  (*env)->ReleaseStringUTFChars(env,device,dev);

  if(pcds[id]==NULL) return (*env)->NewStringUTF(env,pcap_errbuf);

  //set_info(env,obj,pcds[id]);
  linktypes[id]=pcap_datalink(pcds[id]);
  return NULL;
}

/**
Open Dumped File
**/
JNIEXPORT jstring JNICALL
Java_jpcap_Jpcap_nativeOpenOffline(JNIEnv *env,jobject obj,jstring filename)
{
  char *file;
  jint id;
  
  set_Java_env(env);

  id=getJpcapID(env,obj);
  jni_envs[id]=env;

  if(pcds[id]!=NULL){
	return (*env)->NewStringUTF(env,"Another Jpcap instance is being used.");
  }

  file=(char *)(*env)->GetStringUTFChars(env,filename,0);

  pcds[id]=pcap_open_offline(file,pcap_errbuf);

  (*env)->ReleaseStringUTFChars(env,filename,file);

  if(pcds[id]==NULL) return (*env)->NewStringUTF(env,pcap_errbuf);

  //set_info(env,obj,pcds[id]);
  linktypes[id]=pcap_datalink(pcds[id]);
  set_Java_env(env);
  return NULL;
}

/**
Close Live Capture Device
**/
JNIEXPORT void JNICALL
Java_jpcap_Jpcap_close(JNIEnv *env,jobject obj)
{
  int id=getJpcapID(env,obj);
  if(pcds[id]!=NULL) pcap_close(pcds[id]);
  //pcds[id]=NULL;
}

/**
Look up device
**/
JNIEXPORT jstring JNICALL
Java_jpcap_Jpcap_lookupDevice(JNIEnv *env,jobject obj)
{
  char *dev=pcap_lookupdev(pcap_errbuf);
  if(dev==NULL){
    return NULL;
  }else
    return (*env)->NewStringUTF(env,dev);
}

/**
Get Interface List
**/
JNIEXPORT jobjectArray JNICALL
Java_jpcap_Jpcap_getDeviceList(JNIEnv *env,jobject obj)
{
#ifndef WIN32
  int sock=socket(AF_INET,SOCK_DGRAM,0);
  struct ifconf ifc;
  struct ifreq *ifr,*last;
  struct ifreq ifrflags;
  pcap_t *pch;

  char names[100][100];
  int total=0,i=0;
  jobjectArray devices=NULL;

  if(sock<0){
    /* error opening socket*/
    return NULL;
  }

  ifc.ifc_len = 1024*sizeof(struct ifreq);
  ifc.ifc_buf=malloc(ifc.ifc_len);

  if(ioctl(sock,SIOCGIFCONF,&ifc)<0 ||
     ifc.ifc_len<sizeof(struct ifreq)){
    /* SIOCGIFCONF error */
    goto FAIL;
  }

  ifr=(struct ifreq *)ifc.ifc_req;
  last=(struct ifreq *)((char *)ifr+ifc.ifc_len);

  while(ifr<last){
    //puts(ifr->ifr_name);
    /* Skip "dummy" and a ":" */
    if(strncmp(ifr->ifr_name,"dummy",5)==0 ||
       strchr(ifr->ifr_name,':')!=NULL)
      goto NEXT;

    for(i=0;i<total;i++){
      if(strcmp(names[i],ifr->ifr_name)==0) goto NEXT;
    }
    /* Check flags */
    memset(&ifrflags,0,sizeof ifrflags);
    strncpy(ifrflags.ifr_name,ifr->ifr_name,sizeof ifrflags.ifr_name);
    if(ioctl(sock,SIOCGIFFLAGS,(char *)&ifrflags)<0){
      if(errno == ENXIO) goto NEXT;
      else goto FAIL;
    }

    if(!(ifrflags.ifr_flags & IFF_UP)) goto NEXT;

    pch=pcap_open_live(ifr->ifr_name,68,0,0,pcap_errbuf);
    if(pch==NULL) goto NEXT;
    pcap_close(pch);

    strcpy(names[total++],ifr->ifr_name);

  NEXT:
#ifdef HAVE_SA_LEN
    ifr=(struct ifreq *)((char *)ifr+ifr->ifr_addr.sa_len+IFNAMSIZ);
#else
    ifr=(struct ifreq *)((char *)ifr+sizeof(struct ifreq));
#endif
  }

  if(total==0) return NULL;
  devices=(*env)->NewObjectArray(env,(jsize)total,
			  (*env)->FindClass(env,"java/lang/String"),NULL);
  for(i=0;i<total;i++){
    (*env)->SetObjectArrayElement(env,devices,i,(*env)->NewStringUTF(env,names[i]));
  }

  free(ifc.ifc_buf);
  close(sock);
  return devices;

FAIL:
  free(ifc.ifc_buf);
  close(sock);
  return NULL;

#else
	wchar_t *dev;
	int i=0,c=0,j=0;
	char buf[256];
	jobjectArray devices=NULL;

	if(dev=(wchar_t *)pcap_lookupdev(pcap_errbuf)){
		if(dev[0]<256) { /*NT/2000*/
			if(dev[0]==0 && dev[1]==0) return NULL; /* no device */
			while(!(dev[i]==0 && dev[i-1]==0)){
				if(dev[i]==0) c++;
				i++;
			}
			devices=(*env)->NewObjectArray(env,(jsize)c,(*env)->FindClass(env,"java/lang/String"),NULL);
			i=0;
			for(j=0;j<c;j++){
				wcstombs(buf,(wchar_t *)(dev+i),255);
				(*env)->SetObjectArrayElement(env,devices,j,(*env)->NewStringUTF(env,buf));
				while(dev[i]!=0) i++;
				i++;
			}
		}else{ /*9x*/
			char *dev9x=(char *)dev;

			if(dev9x[0]==0 && dev9x[1]==0) return NULL; /* no device */
			while(!(dev9x[i]==0 && dev9x[i-1]==0)){
				if(dev9x[i]==0) c++;
				i++;
			}
			devices=(*env)->NewObjectArray(env,(jsize)c,(*env)->FindClass(env,"java/lang/String"),NULL);
			i=0;
			for(j=0;j<c;j++){
				(*env)->SetObjectArrayElement(env,devices,j,(*env)->NewStringUTF(env,(char *)(dev9x+i)));
				while(dev9x[i]!=0) i++;
				i++;
			}
		}
	}

	return devices;
#endif
}

/**
Get Interface Description (for Windows)
**/
JNIEXPORT jobjectArray JNICALL
Java_jpcap_Jpcap_getDeviceDescription(JNIEnv *env,jobject obj)
{
#ifdef WIN32
	wchar_t *dev;
	char *dscr;
	int i=0,c=0,j=0;
	jobjectArray devices=NULL;

	if(dev=(wchar_t *)pcap_lookupdev(pcap_errbuf)){
		if(dev[0]<256) { /*NT/2000*/
			if(dev[0]==0 && dev[1]==0) return NULL; /* no device */
			while(!(dev[i]==0 && dev[i-1]==0)){
				if(dev[i]==0) c++;
				i++;
			}
			devices=(*env)->NewObjectArray(env,(jsize)c,(*env)->FindClass(env,"java/lang/String"),NULL);
			i++;
			dscr=(char *)dev+(i<<1);
			for(j=0;j<c;j++){
				(*env)->SetObjectArrayElement(env,devices,j,(*env)->NewStringUTF(env,dscr));
				while(*dscr++!=0);
			}
		}else{ /*9x*/
			char *dev9x=(char *)dev;

			if(dev9x[0]==0 && dev9x[1]==0) return NULL; /* no device */
			while(!(*dev9x==0 && *(dev9x-1)==0)){
				if(*dev9x==0) c++;
				dev9x++;
			}
			devices=(*env)->NewObjectArray(env,(jsize)c,(*env)->FindClass(env,"java/lang/String"),NULL);
			dev9x++;
			for(j=0;j<c;j++){
				(*env)->SetObjectArrayElement(env,devices,j,(*env)->NewStringUTF(env,dev9x));
				while(*dev9x++!=0);
			}
		}
	}

	return devices;
#else
	return NULL;
#endif
}

/**
Process Packets
**/
JNIEXPORT jint JNICALL
Java_jpcap_Jpcap_processPacket(JNIEnv *env,jobject obj,
			       jint cnt,jobject handler)
{
  jint pkt_cnt;
  jint id=getJpcapID(env,obj);

  jni_envs[id]=env;
//  printf("%d\n",id);
  jpcap_handlers[id]=(*env)->NewGlobalRef(env,handler);

  pkt_cnt=pcap_dispatch(pcds[id],cnt,dispatcher_handler,(u_char *)id);

  (*env)->DeleteGlobalRef(env,jpcap_handlers[id]);
  return pkt_cnt;
}

/**
Loop Packets
**/
JNIEXPORT jint JNICALL
Java_jpcap_Jpcap_loopPacket(JNIEnv *env,jobject obj,
			    jint cnt,jobject handler)
{
  jint pkt_cnt;
  jint id=getJpcapID(env,obj);

  jni_envs[id]=env;
  jpcap_handlers[id]=(*env)->NewGlobalRef(env,handler);

  pkt_cnt=pcap_loop(pcds[id],cnt,dispatcher_handler,(u_char *)id);

  (*env)->DeleteGlobalRef(env,jpcap_handlers[id]);
  return pkt_cnt;
}


/**
Get One Packet
**/
JNIEXPORT jobject JNICALL
Java_jpcap_Jpcap_getPacket(JNIEnv *env,jobject obj)
{
  struct pcap_pkthdr header;
  jobject packet;
  int id=getJpcapID(env,obj);

  u_char *data=(u_char *)pcap_next(pcds[id],&header);
  jni_envs[id]=env;
  get_packet(header,data,&packet,id);
  return packet;
}

/**
Set Filter
**/
JNIEXPORT void JNICALL
Java_jpcap_Jpcap_setFilter(JNIEnv *env,jobject obj,jstring condition,
			   jboolean opt)
{
  char *cdt=(char *)(*env)->GetStringUTFChars(env,condition,0);
  struct bpf_program program;
  int id=getJpcapID(env,obj);

  if(pcap_compile(pcds[id],&program,cdt,(opt==JNI_TRUE?-1:0),netmasks[id])!=0){
    /**error**/
  }
  if(pcap_setfilter(pcds[id],&program)!=0){
    /**error**/
  }

  (*env)->ReleaseStringUTFChars(env,condition,cdt);
}

/**
Update Statistics
**/
JNIEXPORT void JNICALL
Java_jpcap_Jpcap_updateStat(JNIEnv *env,jobject obj)
{
  struct pcap_stat stat;
  jclass Jpcap;
  jfieldID fid;
  int id=getJpcapID(env,obj);

  pcap_stats(pcds[id],&stat);

  Jpcap=(*env)->FindClass(env,"Jpcap");
  fid=(*env)->GetFieldID(env,Jpcap,"received_packets","I");
  (*env)->SetIntField(env,obj,fid,(jint)stat.ps_recv);
  fid=(*env)->GetFieldID(env,Jpcap,"dropped_packets","I");
  (*env)->SetIntField(env,obj,fid,(jint)stat.ps_drop);
}

/**
Get Error Message
**/
JNIEXPORT jstring JNICALL
Java_jpcap_Jpcap_getErrorMessage(JNIEnv *env,jobject obj)
{
  return (*env)->NewStringUTF(env,pcap_errbuf);
}


void dispatcher_handler(u_char *id,const struct pcap_pkthdr *header,
			const u_char *data)
{
  jobject packet;
  int ID=(int)id;

  JNIEnv *env=jni_envs[ID];

//  printf("enter:%d\n",ID);
  get_packet(*header,(u_char *)data,&packet,ID);
//  printf("got packet:%d\n",ID);
  (*env)->CallVoidMethod(env,jpcap_handlers[ID],handleMID,packet);
  DeleteLocalRef(packet);

//  printf("leave:%d\n",ID);
  YIELD();
}

void get_packet(struct pcap_pkthdr header,u_char *data,jobject *packet,int id){

  u_short nproto,tproto;
  u_short clen=header.caplen,hlen;
  u_char *orig_data=data;

  JNIEnv *env=jni_envs[id];

  /**Analyze type of packet **/
  nproto=get_network_type(data,id);
  clen-=datalink_hlen(id);

//  printf("detect:%d\n",id);
  if(clen>0){
    switch(nproto){
    case ETHERTYPE_IP:
      clen-=((struct ip *)skip_datalink_header(data,id))->ip_hl<<2;
      if(clen>0 &&
	 !(ntohs(((struct ip *)skip_datalink_header(data,id))->ip_off)&IP_OFFMASK))
	tproto=((struct ip *)skip_datalink_header(data,id))->ip_p;
      else
	tproto=ETHERTYPE_IP;
      break;
#ifdef INET6
    case ETHERTYPE_IPV6:
      clen-=40;
      if(clen>0){
	u_char *dp=skip_datalink_header(data,id);
	struct ip6_ext *ip6_ext;

	tproto=((struct ip6_hdr *)dp)->ip6_nxt;
	while((tproto==IPPROTO_HOPOPTS || tproto==IPPROTO_DSTOPTS ||
	       tproto==IPPROTO_ROUTING || tproto==IPPROTO_AH ||
	       tproto==IPPROTO_FRAGMENT) && clen>0){
	  switch(tproto){
	  case IPPROTO_HOPOPTS: /* Hop-by-Hop option  */
	  case IPPROTO_DSTOPTS: /* Destination option */
	  case IPPROTO_ROUTING: /* Routing option */
	  case IPPROTO_AH: /* AH option */
	    ip6_ext=(struct ip6_ext *)dp;
	    tproto=ip6_ext->ip6e_nxt;
	    dp+=ip6_ext->ip6e_len;
	    clen-=ip6_ext->ip6e_len;
	    break;
	  case IPPROTO_FRAGMENT: /* Fragment option */
	    ip6_ext=(struct ip6_ext *)dp;
	    tproto=ip6_ext->ip6e_nxt;
	    dp+=16;
	    clen-=16;
	    break;
	  }
	  if(tproto==IPPROTO_ESP || tproto==IPPROTO_NONE)
	    tproto=-1;
	}
      }
      break;
#endif
    case ETHERTYPE_ARP:
      /** XXX - assume that ARP is for Ethernet<->IPv4 **/
      clen-=28;
      if(clen>0) tproto=ETHERTYPE_ARP;
      break;
    default:
      tproto=get_network_type(data,id);
    }
  }

  /** Check for truncated packet */
  if((tproto==IPPROTO_TCP && clen<TCPHDRLEN) ||
     (tproto==IPPROTO_UDP && clen<UDPHDRLEN) ||
     (tproto==IPPROTO_ICMP && clen<ICMPHDRLEN)){
    tproto=-1;
  }

//  printf("create:%d\n",id);
  /** Create packet object **/
  switch(tproto){
  case IPPROTO_TCP:
    *packet=AllocObject(TCPPacket);break;
  case IPPROTO_UDP:
    *packet=AllocObject(UDPPacket);break;
  case IPPROTO_ICMP:
    *packet=AllocObject(ICMPPacket);break;
  default:
    switch(nproto){
    case ETHERTYPE_IP:
      *packet=AllocObject(IPPacket);break;
#ifdef INET6
    case ETHERTYPE_IPV6:
      *packet=AllocObject(IPPacket);break;
#endif
    case ETHERTYPE_ARP:
	case ETHERTYPE_REVARP:
      *packet=AllocObject(ARPPacket);break;
    default:
      *packet=AllocObject(Packet);break;
    }
  }
  (*env)->CallVoidMethod(env,*packet,setPacketValueMID,
			     (jlong)header.ts.tv_sec,(jlong)header.ts.tv_usec,
			     (jint)header.caplen,(jint)header.len);

//  printf("datalink:%d\n",id);
  /** Analyze Datalink**/
  {
	jobject dlpacket=analyze_datalink(env,data,linktypes[id]);
    (*env)->CallVoidMethod(env,*packet,setDatalinkPacketMID,dlpacket);
  }

//  printf("network:%d\n",id);
  /** Analyze Network**/
  data=skip_datalink_header(data,id);
  switch(nproto){
  case ETHERTYPE_IP:
    clen=ntohs(((struct ip *)data)->ip_len);
    hlen=analyze_ip(env,*packet,data);
    break;
#ifdef INET6
  case ETHERTYPE_IPV6:
    clen=ntohs(((struct ip6_hdr *)data)->ip6_plen);
    hlen=analyze_ipv6(env,*packet,data);break;
#endif
  case ETHERTYPE_ARP:
    clen=hlen=analyze_arp(env,*packet,data);break;
  default:
    clen=header.caplen-datalink_hlen(id);
	hlen=0;
    break;
  }
  if(hlen>header.caplen-datalink_hlen(id)) hlen=header.caplen-datalink_hlen(id);
  data+=hlen;
  clen-=hlen;

//  printf("transport:%d\n",id);
  /** Analyze Transport **/
  switch(tproto){
  case IPPROTO_TCP:
    hlen=analyze_tcp(env,*packet,data); break;
  case IPPROTO_UDP:
	hlen=UDPHDRLEN;
    analyze_udp(env,*packet,data); break;
  case IPPROTO_ICMP:
    // updated by Damien Daspit 5/14/01
    //hlen=clen;
    hlen=ICMPHDRLEN;
	analyze_icmp(env,*packet,data,clen);break;
  default:
  {
    /*jbyteArray dataArray=(*jni_env)->NewByteArray(jni_env,clen);
    (*jni_env)->SetByteArrayRegion(jni_env,dataArray,0,clen,data);
    (*jni_env)->CallVoidMethod(jni_env,*packet,setPacketDataMID,dataArray);*/
    hlen=0;
    break;
  }
  }

  clen-=hlen;
  data+=hlen;
  hlen=data-orig_data;
  {
    jbyteArray dataArray=(*env)->NewByteArray(env,hlen);
	(*env)->SetByteArrayRegion(env,dataArray,0,hlen,orig_data);
	(*env)->CallVoidMethod(env,*packet,setPacketHeaderMID,dataArray);
	DeleteLocalRef(dataArray);

	if(clen>0){
		dataArray=(*env)->NewByteArray(env,clen);
		(*env)->SetByteArrayRegion(env,dataArray,0,clen,data);
		(*env)->CallVoidMethod(env,*packet,setPacketDataMID,dataArray);
		DeleteLocalRef(dataArray);
	}else{
		(*env)->CallVoidMethod(env,*packet,setPacketDataMID,
			(*env)->NewByteArray(env,0));
	}
  }
}

void set_Java_env(JNIEnv *env){
  if(Jpcap!=NULL) return;
  GlobalClassRef(Jpcap,"jpcap/Jpcap");
  GlobalClassRef(JpcapHandler,"jpcap/JpcapHandler");
  GlobalClassRef(Packet,"jpcap/Packet");
  GlobalClassRef(DatalinkPacket,"jpcap/DatalinkPacket");
  GlobalClassRef(EthernetPacket,"jpcap/EthernetPacket");
  GlobalClassRef(IPPacket,"jpcap/IPPacket");
  GlobalClassRef(TCPPacket,"jpcap/TCPPacket");
  GlobalClassRef(UDPPacket,"jpcap/UDPPacket");
  GlobalClassRef(ICMPPacket,"jpcap/ICMPPacket");
  GlobalClassRef(IPv6Option,"jpcap/IPv6Option");
  GlobalClassRef(ARPPacket,"jpcap/ARPPacket");
  GlobalClassRef(String,"java/lang/String");
  GlobalClassRef(Thread,"java/lang/Thread");
  GlobalClassRef(UnknownHostException,"java/net/UnknownHostException");
  GlobalClassRef(IOException,"java/io/IOException");

  handleMID=(*env)->GetMethodID(env,JpcapHandler,"handlePacket",
				"(Ljpcap/Packet;)V");
  setPacketValueMID=(*env)->GetMethodID(env,Packet,"setPacketValue",
					"(JJII)V");
  setDatalinkPacketMID=(*env)->GetMethodID(env,Packet,"setDatalinkPacket",
					   "(Ljpcap/DatalinkPacket;)V");
  setPacketHeaderMID=(*env)->GetMethodID(env,Packet,"setPacketHeader","([B)V");
  setPacketDataMID=(*env)->GetMethodID(env,Packet,"setPacketData",
				       "([B)V");
  setEthernetValueMID=(*env)->GetMethodID(env,EthernetPacket,"setValue",
					  "([B[BS)V");
  // updated by Damien Daspit 5/7/01
  setIPValueMID=(*env)->GetMethodID(env,IPPacket,"setIPv4Value",
		 "(BBZZZBZZZSSSSS[B[B)V");
  setIPv4OptionMID=(*env)->GetMethodID(env,IPPacket,"setOption","([B)V");
  // *******************************
  setIPv6ValueMID=(*env)->GetMethodID(env,IPPacket,"setIPv6Value",
				      "(BBISBS[B[B)V");
  addIPv6OptHdrMID=(*env)->GetMethodID(env,IPPacket,"addOptionHeader",
				       "(Ljpcap/IPv6Option;)V");
  // updated by Damien Daspit 5/7/01
  setTCPValueMID=(*env)->GetMethodID(env,TCPPacket,"setValue","(IIJJZZZZZZZZIS)V");
  // *******************************
  setTCPOptionMID=(*env)->GetMethodID(env,TCPPacket,"setOption","([B)V");
  setUDPValueMID=(*env)->GetMethodID(env,UDPPacket,"setValue","(III)V");
  setICMPValueMID=(*env)->GetMethodID(env,ICMPPacket,"setValue","(BBSSS)V");
  setICMPIDMID=(*env)->GetMethodID(env,ICMPPacket,"setID","(II)V");
  setICMPTimestampMID=(*env)->GetMethodID(env,ICMPPacket,"setTimestampValue",
					  "(JJJ)V");
  setICMPRedirectIPMID=(*env)->GetMethodID(env,ICMPPacket,"setRedirectIP",
				       "([B)V");
  setICMPRouterAdMID=(*env)->GetMethodID(env,ICMPPacket,"setRouterAdValue",
					 "(BBS[Ljava/lang/String;[I)V");
  setV6OptValueMID=(*env)->GetMethodID(env,IPv6Option,"setValue",
				       "(BBB)V");
  setV6OptOptionMID=(*env)->GetMethodID(env,IPv6Option,"setOptionData",
					"([B)V");
  setV6OptRoutingMID=(*env)->GetMethodID(env,IPv6Option,"setRoutingOption",
					  "(BB[Ljava/lang/String;)V");
  setV6OptFragmentMID=(*env)->GetMethodID(env,IPv6Option,"setFragmentOption",
					  "(SZI)V");
  setV6OptAHMID=(*env)->GetMethodID(env,IPv6Option,"setAHOption",
				    "(II)V");
  getSourceAddressMID=(*env)->GetMethodID(env,IPPacket,"getSourceAddress",
					  "()[B");
  getDestinationAddressMID=(*env)->GetMethodID(env,IPPacket,
					       "getDestinationAddress",
					       "()[B");
  setARPValueMID=(*env)->GetMethodID(env,ARPPacket,"setValue",
				     "(SSSSS[B[B[B[B)V");
  jpcapID=(*env)->GetFieldID(env,Jpcap,"ID","I");
}
