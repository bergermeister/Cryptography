#ifndef Crypto_Cipher_RSA_h
#define Crypto_Cipher_RSA_h

#include <Types.h>
#include <Cipher/Cipher.h>

namespace GNCrypto
{
   namespace NCipher
   {
      class TcRSA : public TcCipher
      {
      private:    // Private Attributes
         Ti64 vlN;
         Ti64 vlE;
         Ti64 vlD;

      public:     // Public Methods
         TcRSA( void );
         TcRSA( const TcRSA& aorCipher );
         ~TcRSA( void );
         TcRSA& operator=( const TcRSA& aorCipher );

         void MInitialize( Ti64 alP, Ti64 alQ, Ti64 alI = 0 );
         virtual void MEncrypt( const Tu8* aucpPlaintext, Tu8* aucpCiphertext, const Tu64 aulBytes );
         virtual void MDecrypt( const Tu8* aucpCiphertext, Tu8* aucpPlaintext, const Tu64 aulBytes );
      };
   }
}

#endif

