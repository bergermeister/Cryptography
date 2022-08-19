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
         uint64_t MCalculate( const uint64_t adA, const uint64_t adB, const uint64_t adP );
      }
   }
}

#endif

