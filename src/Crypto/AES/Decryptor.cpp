// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/AES/Configuration.h>
#include <Crypto/AES/Decryptor.h>

using namespace Crypto;
using namespace Crypto::NAES128;

TcDecryptor::TcDecryptor( const TcConfiguration& aorConfiguration ) : vorCfg( aorConfiguration )
{
   std::memset( reinterpret_cast< void* >( this->vucpState ), 0, TcConfiguration::XuiSizeKey );
}

TcDecryptor::TcDecryptor( const TcDecryptor& aorDecryptor ) : vorCfg( aorDecryptor.vorCfg )
{
   *this = aorDecryptor;
}

TcDecryptor::~TcDecryptor( void )
{
   // Nothing to destruct
}

TcDecryptor& TcDecryptor::operator=( const TcDecryptor& aorDecryptor )
{
   if( this != &aorDecryptor )
   {

   }

   return( *this );
}

void TcDecryptor::MDecrypt( const Tu8 aucpCiphertext[ TcConfiguration::XuiSizeKey ],
                            Tu8 aucpPlaintext[ TcConfiguration::XuiSizeKey ] )
{
   const Tu32 kuiRounds = TcConfiguration::XuiRounds - 1;   // Minus 1 for Final Round
   const Tu8* kucpEKey  = this->vorCfg.MExpandedKey( );
   Tu32       kuiIdx;

   /// @par Process Design Langauge
   /// -# Initialzie this->vucpState to plaintext
   std::memcpy( reinterpret_cast< void* >( this->vucpState ),
                reinterpret_cast< const void* >( aucpCiphertext ),
                TcConfiguration::XuiSizeKey );

   /// -# Perform Round 1
   this->mAddRoundKey( &kucpEKey[ TcConfiguration::XuiSizeKey * TcConfiguration::XuiRounds ] );
   this->mShiftRows( );
   this->mSubstitute( );

   /// -# Perform Rounds 2 - 10
   for( kuiIdx = kuiRounds; kuiIdx > 0; kuiIdx-- )
   {
      this->mAddRoundKey( &kucpEKey[ TcConfiguration::XuiSizeKey * kuiIdx ] );
      this->mMixColumns( );
      this->mShiftRows( );
      this->mSubstitute( );
   }
   this->mAddRoundKey( &kucpEKey[ TcConfiguration::XuiSizeKey * kuiIdx ] );

   /// -# Copy this->vucpState into plaintext
   std::memcpy( reinterpret_cast< void* >( aucpPlaintext ),
                reinterpret_cast< const void* >( this->vucpState ),
                TcConfiguration::XuiSizeKey );
}

void TcDecryptor::mAddRoundKey( const Tu8* aucpRoundKey )
{
   const Tu64* kulpRKey = reinterpret_cast< const Tu64* >( aucpRoundKey );
   Tu64* kulpState = reinterpret_cast< Tu64* >( this->vucpState );

   kulpState[ 0 ] ^= kulpRKey[ 0 ];
   kulpState[ 1 ] ^= kulpRKey[ 1 ];
}

void TcDecryptor::mSubstitute( void )
{
   const Tu8* kucpIBox = this->vorCfg.MIBox( );
   for( Tu32 kuiI = 0; kuiI < TcConfiguration::XuiSizeKey; kuiI++ )
   {
      this->vucpState[ kuiI ] = kucpIBox[ this->vucpState[ kuiI ] ];
   }
}

void TcDecryptor::mShiftRows( void )
{
   Tu8  kucpTemp[ TcConfiguration::XuiSizeKey ];
   Tu32 kuiI;

   // Column 1
   kucpTemp[ 0 ] = this->vucpState[ 0 ];
   kucpTemp[ 1 ] = this->vucpState[ 13 ];
   kucpTemp[ 2 ] = this->vucpState[ 10 ];
   kucpTemp[ 3 ] = this->vucpState[ 7 ];

   // Column 2
   kucpTemp[ 4 ] = this->vucpState[ 4 ];
   kucpTemp[ 5 ] = this->vucpState[ 1 ];
   kucpTemp[ 6 ] = this->vucpState[ 14 ];
   kucpTemp[ 7 ] = this->vucpState[ 11 ];

   // Column 3
   kucpTemp[ 8 ] = this->vucpState[ 8 ];
   kucpTemp[ 9 ] = this->vucpState[ 5 ];
   kucpTemp[ 10 ] = this->vucpState[ 2 ];
   kucpTemp[ 11 ] = this->vucpState[ 15 ];

   // Column 4
   kucpTemp[ 12 ] = this->vucpState[ 12 ];
   kucpTemp[ 13 ] = this->vucpState[ 9 ];
   kucpTemp[ 14 ] = this->vucpState[ 6 ];
   kucpTemp[ 15 ] = this->vucpState[ 3 ];

   for( kuiI = 0; kuiI < TcConfiguration::XuiSizeKey; kuiI++ )
   {
      this->vucpState[ kuiI ] = kucpTemp[ kuiI ];
   }
}

void TcDecryptor::mMixColumns( void )
{
   Tu8  kucpTemp[ TcConfiguration::XuiSizeKey ];
   Tu32 kuiI;

   kucpTemp[ 0 ] = static_cast< Tu8 >( TcConfiguration::XucpMul14[ this->vucpState[ 0 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 1 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 2 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 3 ] ] );
   kucpTemp[ 1 ] = static_cast< Tu8 >( TcConfiguration::XucpMul9[ this->vucpState[ 0 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 1 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 2 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 3 ] ] );
   kucpTemp[ 2 ] = static_cast< Tu8 >( TcConfiguration::XucpMul13[ this->vucpState[ 0 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 1 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 2 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 3 ] ] );
   kucpTemp[ 3 ] = static_cast< Tu8 >( TcConfiguration::XucpMul11[ this->vucpState[ 0 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 1 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 2 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 3 ] ] );
   
   kucpTemp[ 4 ] = static_cast< Tu8 >( TcConfiguration::XucpMul14[ this->vucpState[ 4 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 5 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 6 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 7 ] ] );
   kucpTemp[ 5 ] = static_cast< Tu8 >( TcConfiguration::XucpMul9[ this->vucpState[ 4 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 5 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 6 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 7 ] ] );
   kucpTemp[ 6 ] = static_cast< Tu8 >( TcConfiguration::XucpMul13[ this->vucpState[ 4 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 5 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 6 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 7 ] ] );
   kucpTemp[ 7 ] = static_cast< Tu8 >( TcConfiguration::XucpMul11[ this->vucpState[ 4 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 5 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 6 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 7 ] ] );

   kucpTemp[ 8 ] = static_cast< Tu8 >( TcConfiguration::XucpMul14[ this->vucpState[ 8 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 9 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 10 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 11 ] ] );
   kucpTemp[ 9 ] = static_cast< Tu8 >( TcConfiguration::XucpMul9[ this->vucpState[ 8 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 9 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 10 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 11 ] ] );
   kucpTemp[ 10 ] = static_cast< Tu8 >( TcConfiguration::XucpMul13[ this->vucpState[ 8 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 9 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 10 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 11 ] ] );
   kucpTemp[ 11 ] = static_cast< Tu8 >( TcConfiguration::XucpMul11[ this->vucpState[ 8 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 9 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 10 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 11 ] ] );

   kucpTemp[ 12 ] = static_cast< Tu8 >( TcConfiguration::XucpMul14[ this->vucpState[ 12 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 13 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 14 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 15 ] ] );
   kucpTemp[ 13 ] = static_cast< Tu8 >( TcConfiguration::XucpMul9[ this->vucpState[ 12 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 13 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 14 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 15 ] ] );
   kucpTemp[ 14 ] = static_cast< Tu8 >( TcConfiguration::XucpMul13[ this->vucpState[ 12 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 13 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 14 ] ] ^ TcConfiguration::XucpMul11[ this->vucpState[ 15 ] ] );
   kucpTemp[ 15 ] = static_cast< Tu8 >( TcConfiguration::XucpMul11[ this->vucpState[ 12 ] ] ^ TcConfiguration::XucpMul13[ this->vucpState[ 13 ] ] ^ TcConfiguration::XucpMul9[ this->vucpState[ 14 ] ] ^ TcConfiguration::XucpMul14[ this->vucpState[ 15 ] ] );

   for( kuiI = 0; kuiI < TcConfiguration::XuiSizeKey; kuiI++ )
   {
      this->vucpState[ kuiI ] = kucpTemp[ kuiI ];
   }
}

