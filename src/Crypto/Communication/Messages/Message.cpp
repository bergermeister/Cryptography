// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/SHA512.h>
#include <Crypto/Communication/Messages/Message.h>

using namespace Crypto;
using namespace Crypto::NCommunication::NMessages;

void TcMessage::MPrepare( void )
{
   this->voSHA.MInitialize( );
   this->voSHA.MProcess( reinterpret_cast< const uint8_t* >( &this->vuiID ), this->vuiLength );
   this->voSHA.MFinalize( );
}

bool TcMessage::MValid( void ) const
{
   NHash::TcSHA512 koSHA;
   int32_t            kiResult;

   koSHA.MInitialize( );
   koSHA.MProcess( reinterpret_cast< const uint8_t* >( &this->vuiID ), this->vuiLength );
   koSHA.MFinalize( );

   kiResult = std::memcmp( reinterpret_cast< const void* >( this->voSHA.MDigest( ) ),
                           reinterpret_cast< const void* >( koSHA.MDigest( ) ),
                           this->vuiLength );

   return( kiResult == 0 );
}

TcMessage::TcMessage( const uint32_t auiLength, const uint32_t auiID )
{
   this->vuiLength = auiLength;
   this->vuiID     = auiID;
}

TcMessage::TcMessage( const TcMessage& aorMsg )
{
   *this = aorMsg;
}

TcMessage::~TcMessage( void )
{
   // Nothing to destruct
}

TcMessage& TcMessage::operator=( const TcMessage& aorMsg )
{
   if( this != &aorMsg )
   {
      this->vuiID     = aorMsg.vuiID;
      this->vuiLength = aorMsg.vuiLength;
   }

   return( *this );
}
