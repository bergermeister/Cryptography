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
         Tu64 vulP;           ///< Prime Number
         Tu64 vulG;           ///< Prime root modulo P
         Tu64 vulSharedKey;   ///< Shared Key

      public:     // Public Attributes
         TcPublicKey( void );
         TcPublicKey( const TcPublicKey& aorPublicKey );
         ~TcPublicKey( void );
         TcPublicKey& operator=( const TcPublicKey& aorPublicKey );

         void MUpdate( const Tu64 aulP, const Tu64 aulG, const Tu64 aulPrivateKey );

         const Tu64 MP( void ) const;
         const Tu64 MG( void ) const;
         const Tu64 MSharedKey( void ) const;
      };
   }
}

#endif

