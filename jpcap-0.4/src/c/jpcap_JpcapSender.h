/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class jpcap_JpcapSender */

#ifndef _Included_jpcap_JpcapSender
#define _Included_jpcap_JpcapSender
#ifdef __cplusplus
extern "C" {
#endif
#undef jpcap_JpcapSender_MAX_NUMBER_OF_INSTANCE
#define jpcap_JpcapSender_MAX_NUMBER_OF_INSTANCE 10L
/* Inaccessible static: instanciatedFlag */
/*
 * Class:     jpcap_JpcapSender
 * Method:    openRawSocket
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_jpcap_JpcapSender_openRawSocket
  (JNIEnv *, jobject, jstring);

/*
 * Class:     jpcap_JpcapSender
 * Method:    sendPacket
 * Signature: (Ljpcap/IPPacket;)V
 */
JNIEXPORT void JNICALL Java_jpcap_JpcapSender_sendPacket
  (JNIEnv *, jobject, jobject);

#ifdef __cplusplus
}
#endif
#endif
