// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/KeyExchange/DiffieHellman.h>

// StdLib Includes
#include <math.h>

using namespace Crypto;
using namespace Crypto::NKeyExchange;

Tu64 NDiffieHellman::MCalculate( const Tu64 adA, const Tu64 adB, const Tu64 adP )
{
   return( static_cast< Tu64 >( pow( static_cast< Tf64 >( adA ), static_cast< Tf64 >( adB ) ) ) % adP );
}