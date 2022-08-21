// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/SHA512.h>
#include <Crypto/Communication/Messages/Message.h>

using namespace Crypto;
using namespace Crypto::Communication::Messages;

void Message::Prepare( void )
{
   this->sha.Initialize( );
   this->sha.Process( reinterpret_cast< const uint8_t* >( &this->id ), this->length );
   this->sha.Finalize( );
}

bool Message::Valid( void ) const
{
   Hash::SHA512 koSHA;
   int32_t            kiResult;

   koSHA.Initialize( );
   koSHA.Process( reinterpret_cast< const uint8_t* >( &this->id ), this->length );
   koSHA.Finalize( );

   kiResult = std::memcmp( reinterpret_cast< const void* >( this->sha.Digest( ) ),
                           reinterpret_cast< const void* >( koSHA.Digest( ) ),
                           this->length );

   return( kiResult == 0 );
}

Message::Message( const uint32_t auiLength, const uint32_t auiID )
{
   this->length = auiLength;
   this->id     = auiID;
}

Message::Message( const Message& aorMsg )
{
   *this = aorMsg;
}

Message::~Message( void )
{
   // Nothing to destruct
}

Message& Message::operator=( const Message& aorMsg )
{
   if( this != &aorMsg )
   {
      this->id     = aorMsg.id;
      this->length = aorMsg.length;
   }

   return( *this );
}
