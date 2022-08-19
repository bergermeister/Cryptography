// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/KeyExchange/PublicKey.h>
#include <Crypto/KeyExchange/DiffieHellman.h>

using namespace Crypto;
using namespace Crypto::NKeyExchange;

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

void TcPublicKey::MUpdate( const uint64_t aulP, const uint64_t aulG, const uint64_t aulPrivateKey )
{
   this->vulP         = aulP;
   this->vulG         = aulG;
   this->vulSharedKey = NDiffieHellman::MCalculate( this->vulG, aulPrivateKey, this->vulP );
}

const uint64_t TcPublicKey::MP( void ) const
{
   return( this->vulP );
}

const uint64_t TcPublicKey::MG( void ) const
{
   return( this->vulG );
}

const uint64_t TcPublicKey::MSharedKey( void ) const
{
   return( this->vulSharedKey );
}

