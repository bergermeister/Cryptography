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

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/AES/Configuration.h>
#include <Crypto/AES/Encryptor.h>
#include <Crypto/AES/Decryptor.h>
#include <Crypto/Communication/Messages/EstablishSession.h>

/// Namespace containing Cryptograpic functionality
namespace Crypto
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
         uint64_t                     vulpPrivateKey[ NMessages::TcEstablishSession::XuiCountKeys ];
         uint64_t                     vulpSharedSecret[ NMessages::TcEstablishSession::XuiCountKeys ];
         uint8_t                      vucpHash[ NMessages::TcEstablishSession::XuiCountKeys ][ NHash::TcSHA512::XuiLength ];
         NAES128::TcConfiguration voConfig;
         NAES128::TcEncryptor     voEncryptor;
         NAES128::TcDecryptor     voDecryptor;

      public:     // Public Methods
         TcSession( const uint64_t aulpPrivateKey[ NMessages::TcEstablishSession::XuiCountKeys ] );
         TcSession( const TcSession& aorSession );
         ~TcSession( void );
         TcSession& operator=( const TcSession& aorSession );

         NMessages::TcEstablishSession MRequest( void );
         NMessages::TcEstablishSession MEstablish( const NMessages::TcEstablishSession& aorRequest, bool abDynamicSBox );

         NAES128::TcConfiguration& SConfiguration( void );

         void MEncrypt( const uint8_t* aucpPlaintext,  uint8_t* aucpCiphertext, const size_t auiBytes );
         void MDecrypt( const uint8_t* aucpCiphertext, uint8_t* aucpPlaintext,  const size_t auiBytes );
      };
   }
}

#endif
