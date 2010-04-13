#include<pcap.h>
#include<jni.h>

#include"jpcap_JpcapWriter.h"
#include"Jpcap_sub.h"

pcap_t *pcdd=NULL;
pcap_dumper_t *pdt=NULL;

/* Because I can't use sizeof(pcap_t), I must define the size
of pcap_t by myself (without ERRBUF_SIZE). It was 106 on FreeBSD,
so I set it little bit bigger */
#define SIZE_OF_PCAP 200

JNIEXPORT jstring JNICALL
Java_jpcap_JpcapWriter_nativeOpenDumpFile(JNIEnv *env,jobject obj,jstring filename,
										  jint id){
  char *file;

  file=(char *)(*env)->GetStringUTFChars(env,filename,0);
  
  pcdd=pcds[id];
  pdt=pcap_dump_open(pcds[id],file);

  (*env)->ReleaseStringUTFChars(env,filename,file);

  if(pdt==NULL){
	  return (*env)->NewStringUTF(env,pcap_geterr(pcds[id]));
  }

  set_Java_env(env);
  return NULL;
}

JNIEXPORT void JNICALL
Java_jpcap_JpcapWriter_closeDumpFile(JNIEnv *env,jobject obj){
	if(pdt!=NULL){
		pcap_dump_close(pdt);
		free(pcdd);
		pcdd=NULL;
	}
	pdt=NULL;
}

JNIEXPORT void JNICALL
Java_jpcap_JpcapWriter_writeDumpFile(JNIEnv *env,jobject obj,jobject packet){
	jbyteArray header,body;
	int hlen,blen;
	struct pcap_pkthdr hdr;
	char buf[MAX_PACKET_SIZE];

	hdr.ts.tv_sec=(long)GetLongField(Packet,packet,"sec");
	hdr.ts.tv_usec=(long)GetLongField(Packet,packet,"usec");
	hdr.caplen=GetIntField(Packet,packet,"caplen");
	hdr.len=GetIntField(Packet,packet,"len");

	header=GetObjectField(Packet,packet,"[B","header");
	body=GetObjectField(Packet,packet,"[B","data");

	hlen=(*env)->GetArrayLength(env,header);
	blen=(*env)->GetArrayLength(env,body);

	(*env)->GetByteArrayRegion(env,header,0,hlen,buf);
	(*env)->GetByteArrayRegion(env,body,0,blen,(char *)(buf+hlen));

	pcap_dump((u_char *)pdt,&hdr,buf);
}
