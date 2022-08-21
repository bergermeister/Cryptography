/**
 * @file
 * This package contains the Public Key class for Diffie-Hellman exchange.
 */
#ifndef Crypto_KeyExchange_PublicKey_h
#define Crypto_KeyExchange_PublicKey_h

#include <Crypto/Types.h>

/// Namespace containing Cryptograpic functionality
namespace Crypto
{
   /// Namespace containing Key Exchange functionality
   namespace KeyExchange
   {
      class PublicKey
      {
      private:    // Private Attributes
         uint64_t p;           ///< Prime Number
         uint64_t g;           ///< Prime root modulo P
         uint64_t sharedKey;   ///< Shared Key

      public:     // Public Attributes
         PublicKey( void );
         PublicKey( const PublicKey& aorPublicKey );
         ~PublicKey( void );
         PublicKey& operator=( const PublicKey& aorPublicKey );

         void Update( const uint64_t aulP, const uint64_t aulG, const uint64_t aulPrivateKey );

         const uint64_t P( void ) const;
         const uint64_t G( void ) const;
         const uint64_t SharedKey( void ) const;
      };
   }
}

#endif

