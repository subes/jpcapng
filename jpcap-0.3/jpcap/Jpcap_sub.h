/* Comment out next line to enable IPv6 capture*/
//#define INET6 1

/* Comment out next line if you get an error 
   "structure has no member name 'sa_lan" */
#define HAVE_SA_LEN

/* for debugging */
//#define DEBUG


#define IPv4HDRLEN 20
#define TCPHDRLEN 20
#define UDPHDRLEN 8
#define ICMPHDRLEN 8
#define MAX_PACKET_SIZE 1600

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

#define AllocObject(cls)    (*jni_env)->AllocObject(jni_env,cls)
#define NewString(str)      (*jni_env)->NewStringUTF(jni_env,str)
#define DeleteLocalRef(ref) (*jni_env)->DeleteLocalRef(jni_env,ref)
#define GlobalClassRef(cls,str)\
     cls=(*env)->FindClass(env,str);\
     cls=(*env)->NewGlobalRef(env,cls)
#define GetStringChars(str) (*env)->GetStringUTFChars(env,str,0)
#define ReleaseStringChars(str,ary) (*env)->ReleaseStringUTFChars(env,str,ary)
#define IsInstanceOf(cls,obj) (*env)->IsInstanceOf(env,cls,obj)
#define Throw(cls,msg) (*env)->ThrowNew(env,cls,msg)
#define GetIntField(cls,obj,name)\
     (*env)->GetIntField(env,obj,(*env)->GetFieldID(env,cls,name,"I"))
#define GetByteField(cls,obj,name)\
     (*env)->GetByteField(env,obj,(*env)->GetFieldID(env,cls,name,"B"))
#define GetShortField(cls,obj,name)\
     (*env)->GetShortField(env,obj,(*env)->GetFieldID(env,cls,name,"S"))
#define GetLongField(cls,obj,name)\
     (*env)->GetLongField(env,obj,(*env)->GetFieldID(env,cls,name,"J"))
#define GetBooleanField(cls,obj,name)\
     ((*env)->GetBooleanField(env,obj,\
			      (*env)->GetFieldID(env,cls,name,"Z"))?1:0)
#define GetObjectField(cls,obj,type,name)\
     (*env)->GetObjectField(env,obj,(*env)->GetFieldID(env,cls,name,type))
#define YIELD()\
     (*jni_env)->CallStaticVoidMethod(jni_env,Thread,\
		(*jni_env)->GetStaticMethodID(jni_env,Thread,"yield","()V"));

extern int linktype;
 
extern jclass JpcapHandler,Packet,DatalinkPacket,EthernetPacket,IPPacket,
       TCPPacket,UDPPacket,ICMPPacket,IPv6Option,ARPPacket,String,Thread;
extern jclass UnknownHostException,IOException;
extern jmethodID handleMID,setPacketValueMID,setDatalinkPacketMID,setPacketDataMID,
  setEthernetValueMID,setIPValueMID,setIPv6ValueMID,addIPv6OptHdrMID,
  setTCPValueMID,setTCPOptionMID,setUDPValueMID,
  setICMPValueMID,setICMPIDMID,setICMPTimestampMID,setICMPRedirectIPMID,
  setICMPRouterAdMID,setV6OptValueMID,setV6OptOptionMID,setV6OptFragmentMID,
  setV6OptRoutingMID,setV6OptAHMID,
  setARPValueMID,
  getSourceAddressMID,getDestinationAddressMID;

extern JNIEnv *jni_env;

unsigned short in_cksum(unsigned short *addr,int len);
void set_Java_env(JNIEnv *env);
