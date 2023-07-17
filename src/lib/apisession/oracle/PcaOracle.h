/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class PcaOracle */

#ifndef _Included_PcaOracle
#define _Included_PcaOracle
#ifdef __cplusplus
extern "C"
{
#endif
  /*
   * Class:     PcaOracle
   * Method:    INIT
   * Signature: ([B[B)I
   */
  JNIEXPORT jint JNICALL Java_PcaOracle_INIT(JNIEnv *, jclass, jbyteArray, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    OPN
   * Signature: (I[B[B[B[B[BI[B[B)I
   */
  JNIEXPORT jint JNICALL Java_PcaOracle_OPN(JNIEnv *, jclass, jint, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jint, jbyteArray, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    CLS
   * Signature: (I)V
   */
  JNIEXPORT void JNICALL Java_PcaOracle_CLS(JNIEnv *, jclass, jint);

  /*
   * Class:     PcaOracle
   * Method:    CCS
   * Signature: (I[B)V
   */
  JNIEXPORT void JNICALL Java_PcaOracle_CCS(JNIEnv *, jclass, jint, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    ENC
   * Signature: (II[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC(JNIEnv *, jclass, jint, jint, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    ENC_C
   * Signature: (II[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC_1C(JNIEnv *, jclass, jint, jint, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    ENC_NM
   * Signature: (I[B[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC_1NM(JNIEnv *, jclass, jint, jbyteArray, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    DEC
   * Signature: (II[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_DEC(JNIEnv *, jclass, jint, jint, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    DEC_NM
   * Signature: (I[B[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_DEC_1NM(JNIEnv *, jclass, jint, jbyteArray, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    OPHUEK
   * Signature: (II[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_OPHUEK(JNIEnv *, jclass, jint, jint, jbyteArray, jint);

  /*
   * Class:     PcaOracle
   * Method:    OPHUEK_NM
   * Signature: (I[B[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_OPHUEK_1NM(JNIEnv *, jclass, jint, jbyteArray, jbyteArray, jint);

  /*
   * Class:     PcaOracle
   * Method:    ENC_CPN
   * Signature: (II[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC_1CPN(JNIEnv *, jclass, jint, jint, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    ENC_CPN_NM
   * Signature: (I[B[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC_1CPN_1NM(JNIEnv *, jclass, jint, jbyteArray, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    DEC_CPN
   * Signature: (II[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_DEC_1CPN(JNIEnv *, jclass, jint, jint, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    DEC_CPN_NM
   * Signature: (I[B[B)[B
   */
  JNIEXPORT jbyteArray JNICALL Java_PcaOracle_DEC_1CPN_1NM(JNIEnv *, jclass, jint, jbyteArray, jbyteArray);

  /*
   * Class:     PcaOracle
   * Method:    SSHT
   * Signature: (III)I
   */
  JNIEXPORT jint JNICALL Java_PcaOracle_SSHT(JNIEnv *, jclass, jint, jint, jint);

  /*
   * Class:     PcaOracle
   * Method:    SSHT64
   * Signature: (I[BI)I
   */
  JNIEXPORT jint JNICALL Java_PcaOracle_SSHT64(JNIEnv *, jclass, jint, jbyteArray, jint);

  /*
   * Class:     PcaOracle
   * Method:    LCR
   * Signature: (III)I
   */
  JNIEXPORT jint JNICALL Java_PcaOracle_LCR(JNIEnv *, jclass, jint, jint, jint);

  /*
   * Class:     PcaOracle
   * Method:    LCR64
   * Signature: (I[BI)I
   */
  JNIEXPORT jint JNICALL Java_PcaOracle_LCR64(JNIEnv *, jclass, jint, jbyteArray, jint);

  /*
   * Class:     PcaOracle
   * Method:    ECODE
   * Signature: (I)I
   */
  JNIEXPORT jint JNICALL Java_PcaOracle_ECODE(JNIEnv *, jclass, jint);

  /*
   * Class:     PcaOracle
   * Method:    GNSF
   * Signature: (I)I
   */
  JNIEXPORT jint JNICALL Java_PcaOracle_GNSF(JNIEnv *, jclass, jint);

  /*
   * Class:     PcaOracle
   * Method:    LOGGING
   * Signature: (I[B)V
   */
  JNIEXPORT void JNICALL Java_PcaOracle_LOGGING(JNIEnv *, jclass, jint, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
