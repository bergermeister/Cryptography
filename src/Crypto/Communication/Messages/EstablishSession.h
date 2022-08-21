/**
 * @file
 * This package contains the Encrypted Communication Request New Session Message class.
 */
#ifndef Crypto_Communication_Messages_EstablishSession_h
#define Crypto_Communication_Messages_EstablishSession_h

#include <Crypto/Types.h>
#include <Crypto/KeyExchange/PublicKey.h>
#include <Crypto/Communication/Messages/Message.h>

/// Namespace containing Cryptograpic functionality
namespace Crypto
{
   /// Namespace containing encrypted communication functionality
   namespace Communication
   {
      /// Namespace containing encrypted communication messages
      namespace Messages
      {
         /**
          *
          */
         class EstablishSession : public Message
         {
         public:     // Public Attributes
            static const uint32_t XuiType      = 1; ///< Message Type Identifier
            static const uint32_t XuiCountKeys = 5; ///< Number of Shared Keys

         private:    // Private Attributes
            KeyExchange::PublicKey voSharedKey[ XuiCountKeys ];

         public:     // Public Methods
            EstablishSession( void );
            EstablishSession( const EstablishSession& aorRequest );
            ~EstablishSession( void );
            EstablishSession& operator=( const EstablishSession& aorRequest );

            KeyExchange::PublicKey& SharedKey( const uint32_t auiIndex );
            const KeyExchange::PublicKey& SharedKey( const uint32_t auiIndex ) const;
         };
      }
   }
}

#endif
