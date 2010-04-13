#include<jni.h>
#include<pcap.h>

#ifndef WIN32
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#else
#include<winsock2.h>
#include<ws2tcpip.h>
//#include<tpipv6.h>
#endif

#include"Jpcap_sub.h"

/** lookup domain name **/
JNIEXPORT jstring JNICALL
Java_jpcap_IPAddress_gethostnamenative(JNIEnv *env,jobject obj,jbyteArray addr)
{
  jbyte *address;
  struct hostent *hp;
#ifdef WIN32
  WORD wVersionRequested = MAKEWORD(1,1);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif

  address=(*env)->GetByteArrayElements(env,addr,0);
  hp=gethostbyaddr(address,4,AF_INET);
  (*env)->ReleaseByteArrayElements(env,addr,address,0);

#ifdef WIN32
  WSACleanup();
#endif
  
  if(hp!=NULL){
    return NewString((const char *)hp->h_name);
  }else{
    Throw(UnknownHostException,"invalid address");
	return NULL;
  }
}

/** lookup domain name from v6 address **/
JNIEXPORT jstring JNICALL
Java_jpcap_IPAddress_gethostname6native(JNIEnv *env,
					  jobject obj,jbyteArray addr)
{
#ifdef INET6
  char address[16];
  struct hostent *hp;

  (*env)->GetByteArrayRegion(env,addr,0,16,address);

  if((hp=gethostbyaddr(address,16,AF_INET6))){
    return NewString((const char *)hp->h_name);
  }else{
    return NULL;
  }
#else
  Throw(UnknownHostException,"IPv6 address is not supported.");
  return NULL;
#endif
}

/** lookup IPv6 address from domain name **/
JNIEXPORT jbyteArray JNICALL
Java_jpcap_IPAddress_getaddr6native(JNIEnv *env,
					  jobject obj,jstring addr)
{
#ifdef INET6
  const char *addr_char=(*env)->GetStringUTFChars(env,addr,0);
  struct addrinfo *addrinfo;
  int error;

  if((error=getaddrinfo(addr_char,NULL,NULL,&addrinfo))==0){
    jbyteArray address=(*env)->NewByteArray(env,16);
	while(addrinfo->ai_family!=PF_INET6) addrinfo=addrinfo->ai_next;
	(*env)->SetByteArrayRegion(env,address,0,16,addrinfo->ai_addr->sa_data);
	freeaddrinfo(addrinfo);
	ReleaseStringChars(addr,addr_char);
	return address;
  }
  //error
  (*env)->ThrowNew(env,UnknownHostException,gai_strerror(error));
  return NULL;
/*  struct hostent *hp;

  if((hp=gethostbyname2(addr_char, AF_INET6))){
    jbyteArray address=(*env)->NewByteArray(env,16);
    (*env)->SetByteArrayRegion(env,address,0,16,hp->h_addr_list[0]);
    ReleaseStringChars(addr,addr_char);
    return address;
  }else{
    (*env)->ThrowNew(env,UnknownHostException,"Couldn't convert v6 addr to host name");
  }
*/
#else
  Throw(UnknownHostException,"IPv6 address is not supported.");
  return NULL;
#endif
}
