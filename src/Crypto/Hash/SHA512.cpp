// Crypto Includes
#include <Crypto/Hash/SHA512.h>

namespace Crypto
{
   namespace Hash
   {
      const uint64_t SHA512::constant[ constantCount ] =
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

      const uint64_t SHA512::defaultHash[ lengthInWords ] =
      {
         0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
         0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
      };

      SHA512::SHA512( void ) : SHA( reinterpret_cast< const uint8_t* >( this->hash ) )
      {
         // Initialize Algorithm
         this->Initialize( );
      }

      SHA512::SHA512( const SHA512& aorSHA ) : SHA( static_cast< const SHA& >( *this ) )
      {
         // Call assignment operator
         *this = aorSHA;
      }

      SHA512::~SHA512( void )
      {
         // Nothing to destruct
      }

      SHA512& SHA512::operator=( const SHA512& aorSHA )
      {
         if( this != &aorSHA )
         {
            SHA::operator=( static_cast< const SHA& >( aorSHA ) );

            memcpy( reinterpret_cast< void* >( this->hash ),
                  reinterpret_cast< const void* >( aorSHA.hash ),
                  lengthInWords );
         }

         return( *this );
      }

      void SHA512::Initialize( void )
      {
         /// @par Process Design Language
         /// -# Set the initial hash to the default
         memcpy( reinterpret_cast< void* >( this->hash ),
               reinterpret_cast< const void* >( defaultHash ),
               Length );

         // Reset the digested byte count and block count
         this->bytesDigested = 0;
      }

      void SHA512::Process( const uint8_t* aucpMessage, const size_t auiLength )
      {
         const uint8_t* block    = aucpMessage;
         size_t         remaining = auiLength;
         uint8_t        buffer[ blockSize ];

         /// @par Process Design Language
         /// -# Process Each Block
         while( remaining >= blockSize )
         {
            this->processBlock( block );
            remaining      -= blockSize;   // Decrement remaining bytes
            block         += blockSize;   // Increment block pointer
            this->bytesDigested += blockSize;   // Increment Digested count
         }

         /// -# If bytes remain
         if( remaining > 0 )
         {
            memcpy( reinterpret_cast< void* >( buffer ),
                  reinterpret_cast< const void* >( block ),
                  remaining );

            this->bytesDigested += remaining;

            buffer[ remaining++ ] = 0x80;
            if( remaining <= padMax )
            {
               memset( reinterpret_cast< void* >( &buffer[ remaining ] ), 0, padEnd - remaining );
               buffer[ 123 ] = static_cast< uint8_t >( this->bytesDigested >> 29 );
               buffer[ 124 ] = static_cast< uint8_t >( this->bytesDigested >> 21 );
               buffer[ 125 ] = static_cast< uint8_t >( this->bytesDigested >> 13 );
               buffer[ 126 ] = static_cast< uint8_t >( this->bytesDigested >>  5 );
               buffer[ 127 ] = static_cast< uint8_t >( this->bytesDigested <<  3 );
            }
            else
            {
               memset( reinterpret_cast< void* >( &buffer[ remaining ] ), 0, blockSize - remaining );
            }

            this->processBlock( buffer );
         }
      }

      void SHA512::Finalize( void )
      {
         uint8_t  buffer[ blockSize ];
         uint32_t kuiBytes;
         uint32_t kuiWord;

         kuiBytes = this->bytesDigested % blockSize;

         if( ( kuiBytes == 0 ) || ( kuiBytes >= padMax ) )
         {
            memset( reinterpret_cast< void* >( buffer ), 0, padEnd );

            if( kuiBytes == 0 )
            {
               buffer[ 0 ] = 0x80;
            }

            buffer[ 123 ] = static_cast< uint8_t >( this->bytesDigested >> 29 );
            buffer[ 124 ] = static_cast< uint8_t >( this->bytesDigested >> 21 );
            buffer[ 125 ] = static_cast< uint8_t >( this->bytesDigested >> 13 );
            buffer[ 126 ] = static_cast< uint8_t >( this->bytesDigested >> 5 );
            buffer[ 127 ] = static_cast< uint8_t >( this->bytesDigested << 3 );

            this->processBlock( buffer );
         }

         // Endian swap final digest
         for( kuiWord = 0; kuiWord < lengthInWords; kuiWord++ )
         {
            this->hash[ kuiWord ] = ( ( this->hash[ kuiWord ] >> 56 ) & 0x00000000000000FF ) |
                                       ( ( this->hash[ kuiWord ] >> 40 ) & 0x000000000000FF00 ) |
                                       ( ( this->hash[ kuiWord ] >> 24 ) & 0x0000000000FF0000 ) |
                                       ( ( this->hash[ kuiWord ] >>  8 ) & 0x00000000FF000000 ) |
                                       ( ( this->hash[ kuiWord ] <<  8 ) & 0x000000FF00000000 ) |
                                       ( ( this->hash[ kuiWord ] << 24 ) & 0x0000FF0000000000 ) |
                                       ( ( this->hash[ kuiWord ] << 40 ) & 0x00FF000000000000 ) |
                                       ( ( this->hash[ kuiWord ] << 56 ) & 0xFF00000000000000 );
         }
      }

      void SHA512::processBlock( const uint8_t* aucpBlock )
      {
         uint32_t kuiT;
         uint64_t kulTemp1;
         uint64_t kulTemp2;
         uint64_t kulA;
         uint64_t kulB;
         uint64_t kulC;
         uint64_t kulD;
         uint64_t kulE;
         uint64_t kulF;
         uint64_t kulG;
         uint64_t kulH;
         uint64_t kulpW[ constantCount ];

         /// @par Process Design Language
         /// -# Prepare message schedule
         for( kuiT = 0; kuiT < 16; kuiT++ )
         {
            kulA = static_cast< uint64_t >( *aucpBlock++ ) << 56;
            kulB = static_cast< uint64_t >( *aucpBlock++ ) << 48;
            kulC = static_cast< uint64_t >( *aucpBlock++ ) << 40;
            kulD = static_cast< uint64_t >( *aucpBlock++ ) << 32;
            kulE = static_cast< uint64_t >( *aucpBlock++ ) << 24;
            kulF = static_cast< uint64_t >( *aucpBlock++ ) << 16;
            kulG = static_cast< uint64_t >( *aucpBlock++ ) <<  8;
            kulH = static_cast< uint64_t >( *aucpBlock++ );
            kulpW[ kuiT ] = kulA + kulB + kulC + kulD + kulE + kulF + kulG + kulH;
         }

         for( kuiT = 16; kuiT < constantCount; kuiT++ )
         {
            //kulpW[ kuiT ] = ( mROTR< uint64_t >( kulpW[ kuiT - 2 ], 19 ) ^
            //                  mROTR< uint64_t >( kulpW[ kuiT - 2 ], 61 ) ^
            //                  mSHR<  uint64_t >( kulpW[ kuiT - 2 ], 6 ) ) +
            //                kulpW[ kuiT - 7 ] +
            //                ( mROTR< uint64_t >( kulpW[ kuiT - 15 ], 1 ) ^
            //                  mROTR< uint64_t >( kulpW[ kuiT - 15 ], 8 ) ^
            //                  mSHR<  uint64_t >( kulpW[ kuiT - 15 ], 7 ) ) +
            //                kulpW[ kuiT - 16 ];
            kulpW[ kuiT ] = sig4( kulpW[ kuiT -  2 ] ) + kulpW[ kuiT -  7 ] + 
                           sig3( kulpW[ kuiT - 15 ] ) + kulpW[ kuiT - 16 ];
         }

         /// -# Initialize working variables with previous digest
         kulA = this->hash[ 0 ];
         kulB = this->hash[ 1 ];
         kulC = this->hash[ 2 ];
         kulD = this->hash[ 3 ];
         kulE = this->hash[ 4 ];
         kulF = this->hash[ 5 ];
         kulG = this->hash[ 6 ];
         kulH = this->hash[ 7 ];

         // SHA-512 hash computation (alternate method)
         for( kuiT = 0; kuiT < constantCount; kuiT++ )
         {
            // Calculate Temp1 and Temp2
            kulTemp1 = kulH + sig2( kulE ) + Choose( kulE, kulF, kulG ) + constant[ kuiT ] + kulpW[ kuiT ];
            kulTemp2 = sig1( kulA ) + Majority( kulA, kulB, kulC );
            
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
         this->hash[ 0 ] += kulA;
         this->hash[ 1 ] += kulB;
         this->hash[ 2 ] += kulC;
         this->hash[ 3 ] += kulD;
         this->hash[ 4 ] += kulE;
         this->hash[ 5 ] += kulF;
         this->hash[ 6 ] += kulG;
         this->hash[ 7 ] += kulH;
      }
   }
}

