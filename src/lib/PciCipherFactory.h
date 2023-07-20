/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciCipherFactory
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 10
 *   Description        :       cipher factory
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_CIPHER_FACTORY_H
#define PCI_CIPHER_FACTORY_H

#include "Pci3DesCipher.h"
#include "PciAesCipher.h"
#include "PciAriaCipher.h"
#include "PciDesCipher.h"
#include "PciHightCipher.h"
#include "PciHmacCipher.h"
#include "PciLeaCipher.h"
#include "PciSeed256Cipher.h"
#include "PciSeedCipher.h"
#include "PciShaCipher.h"

class PciCipherFactory {
   private:
    static const dgt_uint8 CIPHER_DFLT = 0;
    static const dgt_uint8 CIPHER_AES = 1;
    static const dgt_uint8 CIPHER_SEED = 2;
    static const dgt_uint8 CIPHER_ARIA = 3;
    static const dgt_uint8 CIPHER_SHA = 4;
    static const dgt_uint8 CIPHER_TDES = 5;
    static const dgt_uint8 CIPHER_AES_B = 6;
    static const dgt_uint8 CIPHER_RSA = 7;
    static const dgt_uint8 CIPHER_DES = 8;
    static const dgt_uint8 CIPHER_HMAC = 9;
    static const dgt_uint8 CIPHER_HIGHT = 10;
    static const dgt_uint8 CIPHER_LEA = 12;

    static const dgt_uint8 CIPHER_LIB_PETRA = 0;
    static const dgt_uint8 CIPHER_LIB_KLIB = 1;
    static const dgt_uint8 CIPHER_LIB_OPENSSL = 2;

    PciAriaCipher* AriaCipher;
    PciSeedCipher* SeedCipher;
    PciSeed256Cipher* Seed256Cipher;
    PciAesCipher* AesCipher;
    Pci3DesCipher* TDesCipher;
    PciDesCipher* DesCipher;
    PciShaCipher* ShaCipher;
    PciHmacCipher* HmacCipher;
    PciHightCipher* HightCipher;
    PciLeaCipher* LeaCipher;

   protected:
   public:
    PciCipherFactory()
        : AriaCipher(0),
          SeedCipher(0),
          Seed256Cipher(0),
          AesCipher(0),
          TDesCipher(0),
          DesCipher(0),
          ShaCipher(0),
          HmacCipher(0),
          HightCipher(0),
          LeaCipher(0) {}
    virtual ~PciCipherFactory() {
        delete AriaCipher;
        delete SeedCipher;
        delete Seed256Cipher;
        delete AesCipher;
        delete TDesCipher;
        delete DesCipher;
        delete ShaCipher;
        delete HmacCipher;
        delete HightCipher;
        delete LeaCipher;
    }

    inline PciCipher* getCipher(dgt_uint8 cipher_type, dgt_uint16 key_size,
                                dgt_uint8 lib_type = CIPHER_LIB_PETRA) {
        if (cipher_type == CIPHER_ARIA) {
            if (AriaCipher == 0) AriaCipher = new PciAriaCipher();
            return AriaCipher;
        } else if (cipher_type == CIPHER_SHA) {
            if (ShaCipher == 0) ShaCipher = new PciShaCipher();
            return ShaCipher;
        } else if (cipher_type <= CIPHER_AES) {
            if (AesCipher == 0) AesCipher = new PciAesCipher();
            return AesCipher;
        } else if (cipher_type == CIPHER_SEED) {
            if (key_size == 128) {
                if (SeedCipher == 0) SeedCipher = new PciSeedCipher();
                return SeedCipher;
            }
            if (key_size == 256) {
                if (Seed256Cipher == 0) Seed256Cipher = new PciSeed256Cipher();
                return Seed256Cipher;
            }
        } else if (cipher_type == CIPHER_TDES) {
            if (TDesCipher == 0) TDesCipher = new Pci3DesCipher();
            return TDesCipher;
        } else if (cipher_type == CIPHER_DES) {
            if (DesCipher == 0) DesCipher = new PciDesCipher();
            return DesCipher;
        } else if (cipher_type == CIPHER_HMAC) {
            if (HmacCipher == 0) HmacCipher = new PciHmacCipher();
            return HmacCipher;
        } else if (cipher_type == CIPHER_HIGHT) {
            if (HightCipher == 0) HightCipher = new PciHightCipher();
            return HightCipher;
        } else if (cipher_type == CIPHER_LEA) {
            if (LeaCipher == 0) LeaCipher = new PciLeaCipher();
            return LeaCipher;
        }
        return 0;
    }
};

#endif
