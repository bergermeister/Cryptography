// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/AES/Configuration.h>
#include <Crypto/AES/Encryptor.h>

using namespace Crypto;
using namespace Crypto::NAES128;

TcEncryptor::TcEncryptor( const TcConfiguration& aorConfiguration ) : vorCfg( aorConfiguration )
{
   std::memset( reinterpret_cast< void* >( this->vucpState ), 0, TcConfiguration::XuiSizeKey );
}

TcEncryptor::TcEncryptor( const TcEncryptor& aorEncryptor ) : vorCfg( aorEncryptor.vorCfg )
{
   *this = aorEncryptor;
}

TcEncryptor::~TcEncryptor( void )
{
   // Nothing to destruct
}

TcEncryptor& TcEncryptor::operator=( const TcEncryptor& aorEncryptor )
{
   if( this != &aorEncryptor )
   {
      
   }

   return( *this );
}

void TcEncryptor::MEncrypt( const Tu8 aucpPlaintext[ TcConfiguration::XuiSizeKey ],
                            Tu8 aucpCiphertext[ TcConfiguration::XuiSizeKey ] )
{
   const Tu32 kuiRounds = TcConfiguration::XuiRounds - 1;   // Minus 1 for Final Round
   const Tu8* kucpEKey  = this->vorCfg.MExpandedKey( );
   Tu32       kuiIdx;

   /// @par Process Design Langauge
   /// -# Initialzie state to plaintext
   std::memcpy( reinterpret_cast< void* >( this->vucpState ),
                reinterpret_cast< const void* >( aucpPlaintext ),
                TcConfiguration::XuiSizeKey );

   /// -# Perform Rounds 1 - 9
   for( kuiIdx = 0; kuiIdx < kuiRounds; kuiIdx++ )
   {
      this->mAddRoundKey( &kucpEKey[ TcConfiguration::XuiSizeKey * kuiIdx ] );
      this->mSubstitute( );
      this->mShiftRows( );
      this->mMixColumns( );      
   }
   this->mAddRoundKey( &kucpEKey[ TcConfiguration::XuiSizeKey * kuiIdx ] );

   /// -# Perform Round 10
   this->mSubstitute( );
   this->mShiftRows( );
   this->mAddRoundKey( &kucpEKey[ TcConfiguration::XuiSizeKey * TcConfiguration::XuiRounds ] );

   /// -# Copy state into ciphertext
   std::memcpy( reinterpret_cast< void* >( aucpCiphertext ),
                reinterpret_cast< const void* >( this->vucpState ),
                TcConfiguration::XuiSizeKey );
}

void TcEncryptor::mAddRoundKey( const Tu8* aucpRoundKey )
{
   const Tu64* kulpRKey  = reinterpret_cast< const Tu64* >( aucpRoundKey );
   Tu64*       kulpState = reinterpret_cast< Tu64*       >( this->vucpState );

   kulpState[ 0 ] ^= kulpRKey[ 0 ];
   kulpState[ 1 ] ^= kulpRKey[ 1 ];
}

void TcEncryptor::mSubstitute( void )
{
   const Tu8* kucpSBox = this->vorCfg.MSBox( );
   for( Tu32 kuiI = 0; kuiI < TcConfiguration::XuiSizeKey; kuiI++ )
   {
      this->vucpState[ kuiI ] = kucpSBox[ this->vucpState[ kuiI ] ];
   }
}

void TcEncryptor::mShiftRows( void )
{
   Tu8  kucpTemp[ TcConfiguration::XuiSizeKey ];
   Tu32 kuiI;

   // Column 1
   kucpTemp[ 0  ] = this->vucpState[  0 ];
   kucpTemp[ 1  ] = this->vucpState[  5 ];
   kucpTemp[ 2  ] = this->vucpState[ 10 ];
   kucpTemp[ 3  ] = this->vucpState[ 15 ];

   // Column 2
   kucpTemp[ 4  ] = this->vucpState[  4 ];
   kucpTemp[ 5  ] = this->vucpState[  9 ];
   kucpTemp[ 6  ] = this->vucpState[ 14 ];
   kucpTemp[ 7  ] = this->vucpState[  3 ];

   // Column 3
   kucpTemp[ 8  ] = this->vucpState[  8 ];
   kucpTemp[ 9  ] = this->vucpState[ 13 ];
   kucpTemp[ 10 ] = this->vucpState[  2 ];
   kucpTemp[ 11 ] = this->vucpState[  7 ];

   // Column 4
   kucpTemp[ 12 ] = this->vucpState[ 12 ];
   kucpTemp[ 13 ] = this->vucpState[  1 ];
   kucpTemp[ 14 ] = this->vucpState[  6 ];
   kucpTemp[ 15 ] = this->vucpState[ 11 ];

   for( kuiI = 0; kuiI < TcConfiguration::XuiSizeKey; kuiI++ )
   {
      this->vucpState[ kuiI ] = kucpTemp[ kuiI ];
   }
}


void TcEncryptor::mMixColumns( void )
{
   Tu8  kucpTemp[ TcConfiguration::XuiSizeKey ];
   Tu32 kuiI;
   
   kucpTemp[ 0 ] = static_cast< Tu8 >( TcConfiguration::XucpMul2[ this->vucpState[ 0 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 1 ] ] ^ this->vucpState[ 2 ] ^ this->vucpState[ 3 ] );
   kucpTemp[ 1 ] = static_cast< Tu8 >( this->vucpState[ 0 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 1 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 2 ] ] ^ this->vucpState[ 3 ] );
   kucpTemp[ 2 ] = static_cast< Tu8 >( this->vucpState[ 0 ] ^ this->vucpState[ 1 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 2 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 3 ] ] );
   kucpTemp[ 3 ] = static_cast< Tu8 >( TcConfiguration::XucpMul3[ this->vucpState[ 0 ] ] ^ this->vucpState[ 1 ] ^ this->vucpState[ 2 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 3 ] ] );

   kucpTemp[ 4 ] = static_cast< Tu8 >( TcConfiguration::XucpMul2[ this->vucpState[ 4 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 5 ] ] ^ this->vucpState[ 6 ] ^ this->vucpState[ 7 ] );
   kucpTemp[ 5 ] = static_cast< Tu8 >( this->vucpState[ 4 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 5 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 6 ] ] ^ this->vucpState[ 7 ] );
   kucpTemp[ 6 ] = static_cast< Tu8 >( this->vucpState[ 4 ] ^ this->vucpState[ 5 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 6 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 7 ] ] );
   kucpTemp[ 7 ] = static_cast< Tu8 >( TcConfiguration::XucpMul3[ this->vucpState[ 4 ] ] ^ this->vucpState[ 5 ] ^ this->vucpState[ 6 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 7 ] ] );
     
   kucpTemp[ 8 ]  = static_cast< Tu8 >( TcConfiguration::XucpMul2[ this->vucpState[ 8 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 9 ] ] ^ this->vucpState[ 10 ] ^ this->vucpState[ 11 ] );
   kucpTemp[ 9 ]  = static_cast< Tu8 >( this->vucpState[ 8 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 9 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 10 ] ] ^ this->vucpState[ 11 ] );
   kucpTemp[ 10 ] = static_cast< Tu8 >( this->vucpState[ 8 ] ^ this->vucpState[ 9 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 10 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 11 ] ] );
   kucpTemp[ 11 ] = static_cast< Tu8 >( TcConfiguration::XucpMul3[ this->vucpState[ 8 ] ] ^ this->vucpState[ 9 ] ^ this->vucpState[ 10 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 11 ] ] );
     
   kucpTemp[ 12 ] = static_cast< Tu8 >( TcConfiguration::XucpMul2[ this->vucpState[ 12 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 13 ] ] ^ this->vucpState[ 14 ] ^ this->vucpState[ 15 ] );
   kucpTemp[ 13 ] = static_cast< Tu8 >( this->vucpState[ 12 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 13 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 14 ] ] ^ this->vucpState[ 15 ] );
   kucpTemp[ 14 ] = static_cast< Tu8 >( this->vucpState[ 12 ] ^ this->vucpState[ 13 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 14 ] ] ^ TcConfiguration::XucpMul3[ this->vucpState[ 15 ] ] );
   kucpTemp[ 15 ] = static_cast< Tu8 >( TcConfiguration::XucpMul3[ this->vucpState[ 12 ] ] ^ this->vucpState[ 13 ] ^ this->vucpState[ 14 ] ^ TcConfiguration::XucpMul2[ this->vucpState[ 15 ] ] );

   for( kuiI = 0; kuiI < TcConfiguration::XuiSizeKey; kuiI++ ) 
   {
      this->vucpState[ kuiI ] = kucpTemp[ kuiI ];
   }
}

