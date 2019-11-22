/**
 * @file
 * @brief
 * 512-Bit Secure Hash Algorithm (SHA-512) Package
 *
 * @details
 * @par
 * This package provides the 512-Bit Secure Hash Algorithm (SHA-512) class.
 */
#include <Types.h>
#include <Hash/SHA.h>
#include <Hash/SHA512.h>
#include <string.h>

using namespace GNCrypto;
using namespace GNCrypto::NHash;

const Tu64 TcSHA512::xulConstant[ xuiConstCnt ] =
{
   0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
   0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
   0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
   0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
   0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
   0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
   0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
   0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
   0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
   0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
   0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
   0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
   0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
   0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
   0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
   0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
   0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
   0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
   0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
   0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

const Tu64 TcSHA512::xulDefaultHash[ xuiLengthWords ] =
{
   0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
   0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

TcSHA512::TcSHA512( void ) : TcSHA( reinterpret_cast< const Tu8* >( this->vulHash ) )
{
   // Initialize Algorithm
   this->MInitialize( );
}

TcSHA512::TcSHA512( const TcSHA512& aorSHA ) : TcSHA( static_cast< const TcSHA& >( *this ) )
{
   // Call assignment operator
   *this = aorSHA;
}

TcSHA512::~TcSHA512( void )
{
   // Nothing to destruct
}

TcSHA512& TcSHA512::operator=( const TcSHA512& aorSHA )
{
   if( this != &aorSHA )
   {
      TcSHA::operator=( static_cast< const TcSHA& >( aorSHA ) );

      memcpy( reinterpret_cast< void* >( this->vulHash ),
              reinterpret_cast< const void* >( aorSHA.vulHash ),
              xuiLengthWords );
   }

   return( *this );
}

void TcSHA512::MInitialize( void )
{
   /// @par Process Design Language
   /// -# Set the initial hash to the default
   memcpy( reinterpret_cast< void* >( this->vulHash ),
           reinterpret_cast< const void* >( xulDefaultHash ),
           XuiLength );

   // Reset the digested byte count and block count
   this->vuiDigested = 0;
}

void TcSHA512::MProcess( const Tu8* aucpMessage, const Tu32 auiLength )
{
   const Tu8* kucpBlock    = aucpMessage;
   Tu32       kuiRemaining = auiLength;
   Tu8        kucpBuffer[ xuiLengthBlock ];

   /// @par Process Design Language
   /// -# Process Each Block
   while( kuiRemaining >= xuiLengthBlock )
   {
      this->mProcessBlock( kucpBlock );
      kuiRemaining      -= xuiLengthBlock;   // Decrement remaining bytes
      kucpBlock         += xuiLengthBlock;   // Increment block pointer
      this->vuiDigested += xuiLengthBlock;   // Increment Digested count
   }

   /// -# If bytes remain
   if( kuiRemaining > 0 )
   {
      memcpy( reinterpret_cast< void* >( kucpBuffer ),
              reinterpret_cast< const void* >( kucpBlock ),
              kuiRemaining );

      this->vuiDigested += kuiRemaining;

      kucpBuffer[ kuiRemaining++ ] = 0x80;
      if( kuiRemaining <= xuiPadMax )
      {
         memset( reinterpret_cast< void* >( &kucpBuffer[ kuiRemaining ] ), 0, xuiPadEnd - kuiRemaining );
         kucpBuffer[ 123 ] = static_cast< Tu8 >( this->vuiDigested >> 29 );
         kucpBuffer[ 124 ] = static_cast< Tu8 >( this->vuiDigested >> 21 );
         kucpBuffer[ 125 ] = static_cast< Tu8 >( this->vuiDigested >> 13 );
         kucpBuffer[ 126 ] = static_cast< Tu8 >( this->vuiDigested >>  5 );
         kucpBuffer[ 127 ] = static_cast< Tu8 >( this->vuiDigested <<  3 );
      }
      else
      {
         memset( reinterpret_cast< void* >( &kucpBuffer[ kuiRemaining ] ), 0, xuiLengthBlock - kuiRemaining );
      }

      this->mProcessBlock( kucpBuffer );
   }
}

void TcSHA512::MFinalize( void )
{
   Tu8  kucpBuffer[ xuiLengthBlock ];
   Tu32 kuiBytes;

   kuiBytes = this->vuiDigested % xuiLengthBlock;

   if( ( kuiBytes == 0 ) || ( kuiBytes >= xuiPadMax ) )
   {
      memset( reinterpret_cast< void* >( kucpBuffer ), 0, xuiPadEnd );

      if( kuiBytes == 0 )
      {
         kucpBuffer[ 0 ] = 0x80;
      }

      kucpBuffer[ 123 ] = static_cast< Tu8 >( this->vuiDigested >> 29 );
      kucpBuffer[ 124 ] = static_cast< Tu8 >( this->vuiDigested >> 21 );
      kucpBuffer[ 125 ] = static_cast< Tu8 >( this->vuiDigested >> 13 );
      kucpBuffer[ 126 ] = static_cast< Tu8 >( this->vuiDigested >> 5 );
      kucpBuffer[ 127 ] = static_cast< Tu8 >( this->vuiDigested << 3 );

      this->mProcessBlock( kucpBuffer );
   }
}

void TcSHA512::mProcessBlock( const Tu8* aucpBlock )
{
   Tu32 kuiT;
   Tu64 kulTemp1;
   Tu64 kulTemp2;
   Tu64 kulA;
   Tu64 kulB;
   Tu64 kulC;
   Tu64 kulD;
   Tu64 kulE;
   Tu64 kulF;
   Tu64 kulG;
   Tu64 kulH;
   Tu64 kulpW[ xuiConstCnt ];

   /// @par Process Design Language
   /// -# Prepare message schedule
   for( kuiT = 0; kuiT < 16; kuiT++ )
   {
      kulA = static_cast< Tu64 >( *aucpBlock++ ) << 56;
      kulB = static_cast< Tu64 >( *aucpBlock++ ) << 48;
      kulC = static_cast< Tu64 >( *aucpBlock++ ) << 40;
      kulD = static_cast< Tu64 >( *aucpBlock++ ) << 32;
      kulE = static_cast< Tu64 >( *aucpBlock++ ) << 24;
      kulF = static_cast< Tu64 >( *aucpBlock++ ) << 16;
      kulG = static_cast< Tu64 >( *aucpBlock++ ) <<  8;
      kulH = static_cast< Tu64 >( *aucpBlock++ );
      kulpW[ kuiT ] = kulA + kulB + kulC + kulD + kulE + kulF + kulG + kulH;
   }

   for( kuiT = 16; kuiT < xuiConstCnt; kuiT++ )
   {
      //kulpW[ kuiT ] = ( mROTR< Tu64 >( kulpW[ kuiT - 2 ], 19 ) ^
      //                  mROTR< Tu64 >( kulpW[ kuiT - 2 ], 61 ) ^
      //                  mSHR<  Tu64 >( kulpW[ kuiT - 2 ], 6 ) ) +
      //                kulpW[ kuiT - 7 ] +
      //                ( mROTR< Tu64 >( kulpW[ kuiT - 15 ], 1 ) ^
      //                  mROTR< Tu64 >( kulpW[ kuiT - 15 ], 8 ) ^
      //                  mSHR<  Tu64 >( kulpW[ kuiT - 15 ], 7 ) ) +
      //                kulpW[ kuiT - 16 ];
      kulpW[ kuiT ] = mSig4( kulpW[ kuiT -  2 ] ) + kulpW[ kuiT -  7 ] + 
                      mSig3( kulpW[ kuiT - 15 ] ) + kulpW[ kuiT - 16 ];
   }

   /// -# Initialize working variables with previous digest
   kulA = this->vulHash[ 0 ];
   kulB = this->vulHash[ 1 ];
   kulC = this->vulHash[ 2 ];
   kulD = this->vulHash[ 3 ];
   kulE = this->vulHash[ 4 ];
   kulF = this->vulHash[ 5 ];
   kulG = this->vulHash[ 6 ];
   kulH = this->vulHash[ 7 ];

   // SHA-512 hash computation (alternate method)
   for( kuiT = 0; kuiT < xuiConstCnt; kuiT++ )
   {
      // Calculate Temp1 and Temp2
      kulTemp1 = kulH + mSig2( kulE ) + mCh( kulE, kulF, kulG ) + xulConstant[ kuiT ] + kulpW[ kuiT ];
      kulTemp2 = mSig1( kulA ) + mMaj( kulA, kulB, kulC );
      
      // Update the working registers
      kulH = kulG;
      kulG = kulF;
      kulF = kulE;
      kulE = kulD + kulTemp1;
      kulD = kulC;
      kulC = kulB;
      kulB = kulA;
      kulA = kulTemp1 + kulTemp2;
   }

   // Update the hash value
   this->vulHash[ 0 ] += kulA;
   this->vulHash[ 1 ] += kulB;
   this->vulHash[ 2 ] += kulC;
   this->vulHash[ 3 ] += kulD;
   this->vulHash[ 4 ] += kulE;
   this->vulHash[ 5 ] += kulF;
   this->vulHash[ 6 ] += kulG;
   this->vulHash[ 7 ] += kulH;
}

