#ifndef Crypto_Cipher_Cipher_h
#define Crypto_Cipher_Cipher_h

#include <Types.h>

namespace GNCrypto
{
   namespace NCipher
   {
      class TcCipher
      {
      public:     // Public Methods
         virtual void MEncrypt( const Tu8* aucpPlaintext, Tu8* aucpCiphertext, const Tu64 aulBytes ) = 0;
         virtual void MDecrypt( const Tu8* aucpCiphertext, Tu8* aucpPlaintext, const Tu64 aulBytes ) = 0;
      };
   }
}

#endif

