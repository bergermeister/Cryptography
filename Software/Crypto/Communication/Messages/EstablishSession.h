/**
 * @file
 * @brief
 * Encrypted Communication Request New Session Message Package
 *
 * @details
 * @par
 * This package contains the Encrypted Communication Request New Session Message class.
 */
#ifndef Crypto_Communication_Messages_EstablishSession_h
#define Crypto_Communication_Messages_EstablishSession_h

#include <Types.h>
#include <KeyExchange/PublicKey.h>
#include <Communication/Messages/Message.h>

/// Namespace containing Cryptograpic functionality
namespace GNCrypto
{
   /// Namespace containing encrypted communication functionality
   namespace NCommunication
   {
      /// Namespace containing encrypted communication messages
      namespace NMessages
      {
         /**
          * @brief
          *
          *
          * @details
          * @par
          *
          */
         class TcEstablishSession : public TcMessage
         {
         public:     // Public Attributes
            static const Tu32 XuiType      = 1; ///< Message Type Identifier
            static const Tu32 XuiCountKeys = 5; ///< Number of Shared Keys

         private:    // Private Attributes
            NKeyExchange::TcPublicKey voSharedKey[ XuiCountKeys ];

         public:     // Public Methods
            TcEstablishSession( void );
            TcEstablishSession( const TcEstablishSession& aorRequest );
            ~TcEstablishSession( void );
            TcEstablishSession& operator=( const TcEstablishSession& aorRequest );

            NKeyExchange::TcPublicKey& MSharedKey( const Tu32 auiIndex );
            const NKeyExchange::TcPublicKey& MSharedKey( const Tu32 auiIndex ) const;
         };
      }
   }
}

#endif
