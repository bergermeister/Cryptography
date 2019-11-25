/**
 * @file
 * @brief
 * Encrypted Communication Message Package
 *
 * @details
 * @par
 * This package contains the Encrypted Communication Message class.
 */
#include <Types.h>
#include <Hash/SHA512.h>
#include <Communication/Messages/Message.h>
#include <cstring>

using namespace GNCrypto;
using namespace GNCrypto::NCommunication::NMessages;

void TcMessage::MPrepare( void )
{
   this->voSHA.MInitialize( );
   this->voSHA.MProcess( reinterpret_cast< const Tu8* >( &this->vuiID ), this->vuiLength );
   this->voSHA.MFinalize( );
}

Tb8 TcMessage::MValid( void ) const
{
   NHash::TcSHA512 koSHA;
   Ti32            kiResult;

   koSHA.MInitialize( );
   koSHA.MProcess( reinterpret_cast< const Tu8* >( &this->vuiID ), this->vuiLength );
   koSHA.MFinalize( );

   kiResult = std::memcmp( reinterpret_cast< const void* >( this->voSHA.MDigest( ) ),
                           reinterpret_cast< const void* >( koSHA.MDigest( ) ),
                           this->vuiLength );

   return( kiResult == 0 );
}

TcMessage::TcMessage( const Tu32 auiLength, const Tu32 auiID )
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
