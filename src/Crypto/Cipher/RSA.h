/**
 * @file RSA.h
 * 
 */
#ifndef Crypto_Cipher_RSA_h
#define Crypto_Cipher_RSA_h

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Cipher/ICipher.h>

namespace Crypto
{
   namespace Cipher
   {
      /**
       * 
       * 
       */
      class RSA : public ICipher
      {
      private:    // Private Attributes
         int64_t n;     ///<
         int64_t e;     ///<
         int64_t d;     ///< 

      public:     // Public Methods
         RSA( void ) = default;
         RSA( const RSA& ) = default;
         ~RSA( void ) = default;
         RSA& operator=( const RSA& aorCipher ) = default;

         void Initialize( const int64_t P, const int64_t Q, int64_t I = 0 );
         virtual void Encrypt( const uint8_t* Plaintext, uint8_t* Ciphertext, const size_t Bytes ) override;
         virtual void Decrypt( const uint8_t* Ciphertext, uint8_t* Plaintext, const size_t Bytes ) override;
      };
   }
}

#endif

