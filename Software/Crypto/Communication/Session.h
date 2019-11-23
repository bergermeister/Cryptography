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
#include <Hash/SHA512.h>
#include <AES/Configuration.h>
#include <AES/Encryptor.h>
#include <AES/Decryptor.h>
#include <Communication/Messages/EstablishSession.h>

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
         Tu64                     vulPrivateKey[ NMessages::TcEstablishSession::XuiCountKeys ];
         Tu64                     vulSharedSecret[ NMessages::TcEstablishSession::XuiCountKeys ];
         NHash::TcSHA512          voSHA;
         NAES128::TcConfiguration voConfig;
         NAES128::TcEncryptor     voEncryptor;
         NAES128::TcDecryptor     voDecryptor;

      public:     // Public Methods
         TcSession( const Tu64 aulpPrivateKey[ NMessages::TcEstablishSession::XuiCountKeys ] );
         TcSession( const TcSession& aorSession );
         ~TcSession( void );
         TcSession& operator=( const TcSession& aorSession );

         NMessages::TcEstablishSession MRequest( void );
         NMessages::TcEstablishSession MEstablish( const NMessages::TcEstablishSession& aorRequest );
      };
   }
}

#endif
