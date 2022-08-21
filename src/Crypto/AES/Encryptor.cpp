// Crypto Includes
#include <Crypto/AES/Encryptor.h>

namespace Crypto
{
   namespace AES128
   {
      Encryptor::Encryptor( const Configuration& aorConfiguration ) : config( aorConfiguration )
      {
         std::memset( reinterpret_cast< void* >( this->state ), 0, Configuration::KeySize );
      }

      Encryptor::Encryptor( const Encryptor& aorEncryptor ) : config( aorEncryptor.config )
      {
         *this = aorEncryptor;
      }

      Encryptor::~Encryptor( void )
      {
         // Nothing to destruct
      }

      Encryptor& Encryptor::operator=( const Encryptor& aorEncryptor )
      {
         if( this != &aorEncryptor )
         {
            
         }

         return( *this );
      }

      void Encryptor::Encrypt( const uint8_t aucpPlaintext[ Configuration::KeySize ],
                               uint8_t aucpCiphertext[ Configuration::KeySize ] )
      {
         const uint32_t kuiRounds = Configuration::Rounds - 1;   // Minus 1 for Final Round
         const uint8_t* kucpEKey  = this->config.ExpandedKey( );
         uint32_t       kuiIdx;

         /// @par Process Design Langauge
         /// -# Initialzie state to plaintext
         std::memcpy( reinterpret_cast< void* >( this->state ),
                     reinterpret_cast< const void* >( aucpPlaintext ),
                     Configuration::KeySize );

         /// -# Perform Rounds 1 - 9
         for( kuiIdx = 0; kuiIdx < kuiRounds; kuiIdx++ )
         {
            this->addRoundKey( &kucpEKey[ Configuration::KeySize * kuiIdx ] );
            this->substitute( );
            this->shiftRows( );
            this->mixColumns( );      
         }
         this->addRoundKey( &kucpEKey[ Configuration::KeySize * kuiIdx ] );

         /// -# Perform Round 10
         this->substitute( );
         this->shiftRows( );
         this->addRoundKey( &kucpEKey[ Configuration::KeySize * Configuration::Rounds ] );

         /// -# Copy state into ciphertext
         std::memcpy( reinterpret_cast< void* >( aucpCiphertext ),
                     reinterpret_cast< const void* >( this->state ),
                     Configuration::KeySize );
      }

      void Encryptor::addRoundKey( const uint8_t* aucpRoundKey )
      {
         const uint64_t* kulpRKey  = reinterpret_cast< const uint64_t* >( aucpRoundKey );
         uint64_t*       kulpState = reinterpret_cast< uint64_t*       >( this->state );

         kulpState[ 0 ] ^= kulpRKey[ 0 ];
         kulpState[ 1 ] ^= kulpRKey[ 1 ];
      }

      void Encryptor::substitute( void )
      {
         const uint8_t* kucpSBox = this->config.SBox( );
         for( uint32_t kuiI = 0; kuiI < Configuration::KeySize; kuiI++ )
         {
            this->state[ kuiI ] = kucpSBox[ this->state[ kuiI ] ];
         }
      }

      void Encryptor::shiftRows( void )
      {
         uint8_t  kucpTemp[ Configuration::KeySize ];
         uint32_t kuiI;

         // Column 1
         kucpTemp[ 0  ] = this->state[  0 ];
         kucpTemp[ 1  ] = this->state[  5 ];
         kucpTemp[ 2  ] = this->state[ 10 ];
         kucpTemp[ 3  ] = this->state[ 15 ];

         // Column 2
         kucpTemp[ 4  ] = this->state[  4 ];
         kucpTemp[ 5  ] = this->state[  9 ];
         kucpTemp[ 6  ] = this->state[ 14 ];
         kucpTemp[ 7  ] = this->state[  3 ];

         // Column 3
         kucpTemp[ 8  ] = this->state[  8 ];
         kucpTemp[ 9  ] = this->state[ 13 ];
         kucpTemp[ 10 ] = this->state[  2 ];
         kucpTemp[ 11 ] = this->state[  7 ];

         // Column 4
         kucpTemp[ 12 ] = this->state[ 12 ];
         kucpTemp[ 13 ] = this->state[  1 ];
         kucpTemp[ 14 ] = this->state[  6 ];
         kucpTemp[ 15 ] = this->state[ 11 ];

         for( kuiI = 0; kuiI < Configuration::KeySize; kuiI++ )
         {
            this->state[ kuiI ] = kucpTemp[ kuiI ];
         }
      }


      void Encryptor::mixColumns( void )
      {
         uint8_t  kucpTemp[ Configuration::KeySize ];
         uint32_t kuiI;
         
         kucpTemp[ 0 ] = static_cast< uint8_t >( Configuration::Mul2[ this->state[ 0 ] ] ^ Configuration::Mul3[ this->state[ 1 ] ] ^ this->state[ 2 ] ^ this->state[ 3 ] );
         kucpTemp[ 1 ] = static_cast< uint8_t >( this->state[ 0 ] ^ Configuration::Mul2[ this->state[ 1 ] ] ^ Configuration::Mul3[ this->state[ 2 ] ] ^ this->state[ 3 ] );
         kucpTemp[ 2 ] = static_cast< uint8_t >( this->state[ 0 ] ^ this->state[ 1 ] ^ Configuration::Mul2[ this->state[ 2 ] ] ^ Configuration::Mul3[ this->state[ 3 ] ] );
         kucpTemp[ 3 ] = static_cast< uint8_t >( Configuration::Mul3[ this->state[ 0 ] ] ^ this->state[ 1 ] ^ this->state[ 2 ] ^ Configuration::Mul2[ this->state[ 3 ] ] );

         kucpTemp[ 4 ] = static_cast< uint8_t >( Configuration::Mul2[ this->state[ 4 ] ] ^ Configuration::Mul3[ this->state[ 5 ] ] ^ this->state[ 6 ] ^ this->state[ 7 ] );
         kucpTemp[ 5 ] = static_cast< uint8_t >( this->state[ 4 ] ^ Configuration::Mul2[ this->state[ 5 ] ] ^ Configuration::Mul3[ this->state[ 6 ] ] ^ this->state[ 7 ] );
         kucpTemp[ 6 ] = static_cast< uint8_t >( this->state[ 4 ] ^ this->state[ 5 ] ^ Configuration::Mul2[ this->state[ 6 ] ] ^ Configuration::Mul3[ this->state[ 7 ] ] );
         kucpTemp[ 7 ] = static_cast< uint8_t >( Configuration::Mul3[ this->state[ 4 ] ] ^ this->state[ 5 ] ^ this->state[ 6 ] ^ Configuration::Mul2[ this->state[ 7 ] ] );
         
         kucpTemp[ 8 ]  = static_cast< uint8_t >( Configuration::Mul2[ this->state[ 8 ] ] ^ Configuration::Mul3[ this->state[ 9 ] ] ^ this->state[ 10 ] ^ this->state[ 11 ] );
         kucpTemp[ 9 ]  = static_cast< uint8_t >( this->state[ 8 ] ^ Configuration::Mul2[ this->state[ 9 ] ] ^ Configuration::Mul3[ this->state[ 10 ] ] ^ this->state[ 11 ] );
         kucpTemp[ 10 ] = static_cast< uint8_t >( this->state[ 8 ] ^ this->state[ 9 ] ^ Configuration::Mul2[ this->state[ 10 ] ] ^ Configuration::Mul3[ this->state[ 11 ] ] );
         kucpTemp[ 11 ] = static_cast< uint8_t >( Configuration::Mul3[ this->state[ 8 ] ] ^ this->state[ 9 ] ^ this->state[ 10 ] ^ Configuration::Mul2[ this->state[ 11 ] ] );
         
         kucpTemp[ 12 ] = static_cast< uint8_t >( Configuration::Mul2[ this->state[ 12 ] ] ^ Configuration::Mul3[ this->state[ 13 ] ] ^ this->state[ 14 ] ^ this->state[ 15 ] );
         kucpTemp[ 13 ] = static_cast< uint8_t >( this->state[ 12 ] ^ Configuration::Mul2[ this->state[ 13 ] ] ^ Configuration::Mul3[ this->state[ 14 ] ] ^ this->state[ 15 ] );
         kucpTemp[ 14 ] = static_cast< uint8_t >( this->state[ 12 ] ^ this->state[ 13 ] ^ Configuration::Mul2[ this->state[ 14 ] ] ^ Configuration::Mul3[ this->state[ 15 ] ] );
         kucpTemp[ 15 ] = static_cast< uint8_t >( Configuration::Mul3[ this->state[ 12 ] ] ^ this->state[ 13 ] ^ this->state[ 14 ] ^ Configuration::Mul2[ this->state[ 15 ] ] );

         for( kuiI = 0; kuiI < Configuration::KeySize; kuiI++ ) 
         {
            this->state[ kuiI ] = kucpTemp[ kuiI ];
         }
      }
   }
}

