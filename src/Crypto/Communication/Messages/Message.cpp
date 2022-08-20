// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/SHA512.h>
#include <Crypto/Communication/Messages/Message.h>

using namespace Crypto;
using namespace Crypto::NCommunication::NMessages;

void TcMessage::MPrepare( void )
{
   this->voSHA.Initialize( );
   this->voSHA.Process( reinterpret_cast< const uint8_t* >( &this->vuiID ), this->vuiLength );
   this->voSHA.Finalize( );
}

bool TcMessage::MValid( void ) const
{
   Hash::SHA512 koSHA;
   int32_t            kiResult;

   koSHA.Initialize( );
   koSHA.Process( reinterpret_cast< const uint8_t* >( &this->vuiID ), this->vuiLength );
   koSHA.Finalize( );

   kiResult = std::memcmp( reinterpret_cast< const void* >( this->voSHA.Digest( ) ),
                           reinterpret_cast< const void* >( koSHA.Digest( ) ),
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
