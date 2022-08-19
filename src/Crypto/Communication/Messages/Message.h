/**
 * @file
 * This package contains the Encrypted Communication Message class.
 */
#ifndef Crypto_Communication_Messages_Message_h
#define Crypto_Communication_Messages_Message_h

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/SHA512.h>

/// Namespace containing Cryptograpic functionality
namespace Crypto
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
         class TcMessage
         {
         private:    // Private attributes
            NHash::TcSHA512 voSHA;     ///< SHA-512 Digest of message
            uint32_t            vuiLength; ///< Length of payload in bytes, not including hash
            uint32_t            vuiID;     ///< Message Type identifier

         public:     // Public Methods
            void MPrepare( void );
            bool  MValid( void ) const;

         protected:  // Protected Methods
            TcMessage( const uint32_t auiLength, const uint32_t auiID );
            TcMessage( const TcMessage& aorMsg );
            ~TcMessage( void );
            TcMessage& operator=( const TcMessage& aorMsg );
         };
      }
   }
}

#endif

