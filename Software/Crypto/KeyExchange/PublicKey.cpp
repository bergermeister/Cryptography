/**
 * @file
 * @brief
 * Public Key Exchange Package
 *
 * @details
 * @par
 * This package contains the Public Key class for Diffie-Hellman exchange.
 */
#include <Types.h>
#include <KeyExchange/PublicKey.h>
#include <KeyExchange/DiffieHellman.h>

using namespace GNCrypto;
using namespace GNCrypto::NKeyExchange;

TcPublicKey::TcPublicKey( void )
{
   // Nothing to construct
}

TcPublicKey::TcPublicKey( const TcPublicKey& aorPublicKey )
{
   *this = aorPublicKey;
}

TcPublicKey::~TcPublicKey( void )
{
   // Nothing to destruct
}

TcPublicKey& TcPublicKey::operator=( const TcPublicKey& aorPublicKey )
{
   if( this != &aorPublicKey )
   {
      this->vulP         = aorPublicKey.vulP;
      this->vulG         = aorPublicKey.vulG;
      this->vulSharedKey = aorPublicKey.vulSharedKey;
   }

   return( *this );
}

void TcPublicKey::MUpdate( const Tu64 aulP, const Tu64 aulG, const Tu64 aulPrivateKey )
{
   this->vulP         = aulP;
   this->vulG         = aulG;
   this->vulSharedKey = NDiffieHellman::MCalculate( this->vulG, aulPrivateKey, this->vulP );
}

const Tu64 TcPublicKey::MP( void ) const
{
   return( this->vulP );
}

const Tu64 TcPublicKey::MG( void ) const
{
   return( this->vulG );
}

const Tu64 TcPublicKey::MSharedKey( void ) const
{
   return( this->vulSharedKey );
}

