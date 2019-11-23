/**
 * @file
 * @brief
 * Encrypted Communication Session Package
 *
 * @details
 * @par
 * This package contains the Encrypted Communication Session class.
 */
#ifndef Crypto_Communication_Session_h
#define Crypto_Communication_Session_h

#include <Types.h>
#include <AES/Configuration.h>
#include <AES/Encryptor.h>
#include <AES/Decryptor.h>

 /// Namespace containing Cryptograpic functionality
namespace GNCrypto
{
   /// Namespace containing encrypted communication functionality
   namespace NCommunication
   {
      /**
       * @brief
       *
       *
       * @details
       * @par
       *
       */
      class TcSession
      {
      private:    // Private Attributes
         NAES128::TcConfiguration voConfig;
         NAES128::TcEncryptor     voEncryptor;
         NAES128::TcDecryptor     voDecryptor;

      public:     // Public Methods
         TcSession( void );
         TcSession( const TcSession& aorSession );
         ~TcSession( void );
         TcSession& operator=( const TcSession& aorSession );


      };
   }
}

#endif
