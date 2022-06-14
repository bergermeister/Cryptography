/**
 * @file
 */
#ifndef Crypto_Cipher_ICipher_h
#define Crypto_Cipher_ICipher_h

// Crypto Includes
#include <Crypto/Types.h>

namespace Crypto
{
   namespace Cipher
   {
      /**
       * Cipher Interface
       */
      class ICipher
      {
      public:     // Public Methods
         virtual void Encrypt( const uint8_t* Plaintext, uint8_t* Ciphertext, const size_t Bytes ) = 0;
         virtual void Decrypt( const uint8_t* Ciphertext, uint8_t* Plaintext, const size_t Bytes ) = 0;
      };
   }
}

#endif

