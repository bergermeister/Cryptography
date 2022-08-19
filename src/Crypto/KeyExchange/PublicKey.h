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
   namespace NKeyExchange
   {
      class TcPublicKey
      {
      private:    // Private Attributes
         uint64_t vulP;           ///< Prime Number
         uint64_t vulG;           ///< Prime root modulo P
         uint64_t vulSharedKey;   ///< Shared Key

      public:     // Public Attributes
         TcPublicKey( void );
         TcPublicKey( const TcPublicKey& aorPublicKey );
         ~TcPublicKey( void );
         TcPublicKey& operator=( const TcPublicKey& aorPublicKey );

         void MUpdate( const uint64_t aulP, const uint64_t aulG, const uint64_t aulPrivateKey );

         const uint64_t MP( void ) const;
         const uint64_t MG( void ) const;
         const uint64_t MSharedKey( void ) const;
      };
   }
}

#endif

