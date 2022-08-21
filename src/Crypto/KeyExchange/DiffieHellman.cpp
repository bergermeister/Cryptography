// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/KeyExchange/DiffieHellman.h>

// StdLib Includes
#include <math.h>

using namespace Crypto;
using namespace Crypto::KeyExchange;

uint64_t DiffieHellman::MCalculate( const uint64_t adA, const uint64_t adB, const uint64_t adP )
{
   return( static_cast< uint64_t >( pow( static_cast< double >( adA ), static_cast< double >( adB ) ) ) % adP );
}