/**
 * @file
 * @brief
 * Diffie-Hellman Key Exchange Package
 *
 * @details
 * @par
 * This package contains the Diffie-Hellman Key Exchange API.
 */
#include <Types.h>
#include <KeyExchange/DiffieHellman.h>
#include <math.h>

using namespace GNCrypto;
using namespace GNCrypto::NKeyExchange;

Tu64 NDiffieHellman::MCalculate( const Tu64 adA, const Tu64 adB, const Tu64 adP )
{
   return( static_cast< Tu64 >( pow( static_cast< Tf64 >( adA ), static_cast< Tf64 >( adB ) ) ) % adP );
}