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
         Tu64                     vulpPrivateKey[ NMessages::TcEstablishSession::XuiCountKeys ];
         Tu64                     vulpSharedSecret[ NMessages::TcEstablishSession::XuiCountKeys ];
         Tu8                      vucpHash[ NMessages::TcEstablishSession::XuiCountKeys ][ NHash::TcSHA512::XuiLength ];
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
         void MEncrypt( const Tu8* aucpPlaintext,  Tu8* aucpCiphertext, const Tu32 auiBytes );
         void MDecrypt( const Tu8* aucpCiphertext, Tu8* aucpPlaintext,  const Tu32 auiBytes );
      };
   }
}

#endif
