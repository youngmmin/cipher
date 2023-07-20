/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciDesCipher
 *   Implementor        :       mwpark
 *   Create Date        :       2016. 08. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_DES_CIPHER
#define PCI_DES_CIPHER

#include "PciBlockCipher.h"

#define LOAD32BE(p)                                      \
    (((unsigned int)(((unsigned char *)(p))[0]) << 24) | \
     ((unsigned int)(((unsigned char *)(p))[1]) << 16) | \
     ((unsigned int)(((unsigned char *)(p))[2]) << 8) |  \
     ((unsigned int)(((unsigned char *)(p))[3]) << 0))

#define STORE32BE(a, p)                                           \
    ((unsigned char *)(p))[0] = ((unsigned int)(a) >> 24) & 0xFF, \
                    ((unsigned char *)(p))[1] =                   \
                        ((unsigned int)(a) >> 16) & 0xFF,         \
                    ((unsigned char *)(p))[2] =                   \
                        ((unsigned int)(a) >> 8) & 0xFF,          \
                    ((unsigned char *)(p))[3] =                   \
                        ((unsigned int)(a) >> 0) & 0xFF

#define DES_BLOCK_SIZE 8

typedef struct {
    unsigned int ks[32];
} DesContext;

class PciDesCipher : public PciBlockCipher {
   private:
    int desInit(const unsigned char *key, int keyLength);
    virtual dgt_sint32 initializeContext();
    virtual dgt_sint32 encryptBlock(dgt_uint8 *iblock, dgt_uint8 *oblock);
    virtual dgt_sint32 decryptBlock(dgt_uint8 *iblock, dgt_uint8 *oblock);
    DesContext Context;

   protected:
   public:
    PciDesCipher();
    virtual ~PciDesCipher();
};

#endif
