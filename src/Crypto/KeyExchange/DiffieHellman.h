/**
 * @file
 * This package contains the Diffie-Hellman Key Exchange API.
 */
#ifndef Crypto_KeyExchange_DiffieHellman_h
#define Crypto_KeyExchange_DiffieHellman_h

// Crypto Includes
#include <Crypto/Types.h>

/// Namespace containing Cryptograpic functionality
namespace Crypto
{
   /// Namespace containing Key Exchange functionality
   namespace NKeyExchange
   {
      namespace NDiffieHellman
      {
         Tu64 MCalculate( const Tu64 adA, const Tu64 adB, const Tu64 adP );
      }
   }
}

#endif

