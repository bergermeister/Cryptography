// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/KeyExchange/PublicKey.h>
#include <Crypto/KeyExchange/DiffieHellman.h>

using namespace Crypto;
using namespace Crypto::KeyExchange;

PublicKey::PublicKey( void )
{
   // Nothing to construct
}

PublicKey::PublicKey( const PublicKey& aorPublicKey )
{
   *this = aorPublicKey;
}

PublicKey::~PublicKey( void )
{
   // Nothing to destruct
}

PublicKey& PublicKey::operator=( const PublicKey& aorPublicKey )
{
   if( this != &aorPublicKey )
   {
      this->p         = aorPublicKey.p;
      this->g         = aorPublicKey.g;
      this->sharedKey = aorPublicKey.sharedKey;
   }

   return( *this );
}

void PublicKey::Update( const uint64_t aulP, const uint64_t aulG, const uint64_t aulPrivateKey )
{
   this->p         = aulP;
   this->g         = aulG;
   this->sharedKey = DiffieHellman::MCalculate( this->g, aulPrivateKey, this->p );
}

const uint64_t PublicKey::P( void ) const
{
   return( this->p );
}

const uint64_t PublicKey::G( void ) const
{
   return( this->g );
}

const uint64_t PublicKey::SharedKey( void ) const
{
   return( this->sharedKey );
}

