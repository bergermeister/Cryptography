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
   namespace Communication
   {
      /// Namespace containing encrypted communication messages
      namespace Messages
      {
         /**
          */
         class Message
         {
         private:    // Private attributes
            Hash::SHA512 sha;    ///< SHA-512 Digest of message
            uint32_t     length; ///< Length of payload in bytes, not including hash
            uint32_t     id;     ///< Message Type identifier

         public:     // Public Methods
            void Prepare( void );
            bool Valid( void ) const;

         protected:  // Protected Methods
            Message( const uint32_t auiLength, const uint32_t auiID );
            Message( const Message& aorMsg );
            ~Message( void );
            Message& operator=( const Message& aorMsg );
         };
      }
   }
}

#endif

