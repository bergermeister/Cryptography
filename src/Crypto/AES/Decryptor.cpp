// Crypto Includes
#include <Crypto/AES/Decryptor.h>

namespace Crypto
{
   namespace AES128
   {
      Decryptor::Decryptor( const Configuration& aorConfiguration ) : config( aorConfiguration )
      {
         std::memset( reinterpret_cast< void* >( this->state ), 0, Configuration::KeySize );
      }

      Decryptor::Decryptor( const Decryptor& aorDecryptor ) : config( aorDecryptor.config )
      {
         *this = aorDecryptor;
      }

      Decryptor::~Decryptor( void )
      {
         // Nothing to destruct
      }

      Decryptor& Decryptor::operator=( const Decryptor& aorDecryptor )
      {
         if( this != &aorDecryptor )
         {

         }

         return( *this );
      }

      void Decryptor::Decrypt( const uint8_t aucpCiphertext[ Configuration::KeySize ],
                               uint8_t aucpPlaintext[ Configuration::KeySize ] )
      {
         const uint32_t kuiRounds = Configuration::Rounds - 1;   // Minus 1 for Final Round
         const uint8_t* kucpEKey  = this->config.ExpandedKey( );
         uint32_t       kuiIdx;

         /// @par Process Design Langauge
         /// -# Initialzie this->state to plaintext
         std::memcpy( reinterpret_cast< void* >( this->state ),
                     reinterpret_cast< const void* >( aucpCiphertext ),
                     Configuration::KeySize );

         /// -# Perform Round 1
         this->addRoundKey( &kucpEKey[ Configuration::KeySize * Configuration::Rounds ] );
         this->shiftRows( );
         this->substitute( );

         /// -# Perform Rounds 2 - 10
         for( kuiIdx = kuiRounds; kuiIdx > 0; kuiIdx-- )
         {
            this->addRoundKey( &kucpEKey[ Configuration::KeySize * kuiIdx ] );
            this->mixColumns( );
            this->shiftRows( );
            this->substitute( );
         }
         this->addRoundKey( &kucpEKey[ Configuration::KeySize * kuiIdx ] );

         /// -# Copy this->state into plaintext
         std::memcpy( reinterpret_cast< void* >( aucpPlaintext ),
                     reinterpret_cast< const void* >( this->state ),
                     Configuration::KeySize );
      }

      void Decryptor::addRoundKey( const uint8_t* aucpRoundKey )
      {
         const uint64_t* kulpRKey = reinterpret_cast< const uint64_t* >( aucpRoundKey );
         uint64_t* kulpState = reinterpret_cast< uint64_t* >( this->state );

         kulpState[ 0 ] ^= kulpRKey[ 0 ];
         kulpState[ 1 ] ^= kulpRKey[ 1 ];
      }

      void Decryptor::substitute( void )
      {
         const uint8_t* kucpIBox = this->config.IBox( );
         for( uint32_t kuiI = 0; kuiI < Configuration::KeySize; kuiI++ )
         {
            this->state[ kuiI ] = kucpIBox[ this->state[ kuiI ] ];
         }
      }

      void Decryptor::shiftRows( void )
      {
         uint8_t  kucpTemp[ Configuration::KeySize ];
         uint32_t kuiI;

         // Column 1
         kucpTemp[ 0 ] = this->state[ 0 ];
         kucpTemp[ 1 ] = this->state[ 13 ];
         kucpTemp[ 2 ] = this->state[ 10 ];
         kucpTemp[ 3 ] = this->state[ 7 ];

         // Column 2
         kucpTemp[ 4 ] = this->state[ 4 ];
         kucpTemp[ 5 ] = this->state[ 1 ];
         kucpTemp[ 6 ] = this->state[ 14 ];
         kucpTemp[ 7 ] = this->state[ 11 ];

         // Column 3
         kucpTemp[ 8 ] = this->state[ 8 ];
         kucpTemp[ 9 ] = this->state[ 5 ];
         kucpTemp[ 10 ] = this->state[ 2 ];
         kucpTemp[ 11 ] = this->state[ 15 ];

         // Column 4
         kucpTemp[ 12 ] = this->state[ 12 ];
         kucpTemp[ 13 ] = this->state[ 9 ];
         kucpTemp[ 14 ] = this->state[ 6 ];
         kucpTemp[ 15 ] = this->state[ 3 ];

         for( kuiI = 0; kuiI < Configuration::KeySize; kuiI++ )
         {
            this->state[ kuiI ] = kucpTemp[ kuiI ];
         }
      }

      void Decryptor::mixColumns( void )
      {
         uint8_t  kucpTemp[ Configuration::KeySize ];
         uint32_t kuiI;

         kucpTemp[ 0 ] = static_cast< uint8_t >( Configuration::Mul14[ this->state[ 0 ] ] ^ Configuration::Mul11[ this->state[ 1 ] ] ^ Configuration::Mul13[ this->state[ 2 ] ] ^ Configuration::Mul9[ this->state[ 3 ] ] );
         kucpTemp[ 1 ] = static_cast< uint8_t >( Configuration::Mul9[ this->state[ 0 ] ] ^ Configuration::Mul14[ this->state[ 1 ] ] ^ Configuration::Mul11[ this->state[ 2 ] ] ^ Configuration::Mul13[ this->state[ 3 ] ] );
         kucpTemp[ 2 ] = static_cast< uint8_t >( Configuration::Mul13[ this->state[ 0 ] ] ^ Configuration::Mul9[ this->state[ 1 ] ] ^ Configuration::Mul14[ this->state[ 2 ] ] ^ Configuration::Mul11[ this->state[ 3 ] ] );
         kucpTemp[ 3 ] = static_cast< uint8_t >( Configuration::Mul11[ this->state[ 0 ] ] ^ Configuration::Mul13[ this->state[ 1 ] ] ^ Configuration::Mul9[ this->state[ 2 ] ] ^ Configuration::Mul14[ this->state[ 3 ] ] );
         
         kucpTemp[ 4 ] = static_cast< uint8_t >( Configuration::Mul14[ this->state[ 4 ] ] ^ Configuration::Mul11[ this->state[ 5 ] ] ^ Configuration::Mul13[ this->state[ 6 ] ] ^ Configuration::Mul9[ this->state[ 7 ] ] );
         kucpTemp[ 5 ] = static_cast< uint8_t >( Configuration::Mul9[ this->state[ 4 ] ] ^ Configuration::Mul14[ this->state[ 5 ] ] ^ Configuration::Mul11[ this->state[ 6 ] ] ^ Configuration::Mul13[ this->state[ 7 ] ] );
         kucpTemp[ 6 ] = static_cast< uint8_t >( Configuration::Mul13[ this->state[ 4 ] ] ^ Configuration::Mul9[ this->state[ 5 ] ] ^ Configuration::Mul14[ this->state[ 6 ] ] ^ Configuration::Mul11[ this->state[ 7 ] ] );
         kucpTemp[ 7 ] = static_cast< uint8_t >( Configuration::Mul11[ this->state[ 4 ] ] ^ Configuration::Mul13[ this->state[ 5 ] ] ^ Configuration::Mul9[ this->state[ 6 ] ] ^ Configuration::Mul14[ this->state[ 7 ] ] );

         kucpTemp[ 8 ] = static_cast< uint8_t >( Configuration::Mul14[ this->state[ 8 ] ] ^ Configuration::Mul11[ this->state[ 9 ] ] ^ Configuration::Mul13[ this->state[ 10 ] ] ^ Configuration::Mul9[ this->state[ 11 ] ] );
         kucpTemp[ 9 ] = static_cast< uint8_t >( Configuration::Mul9[ this->state[ 8 ] ] ^ Configuration::Mul14[ this->state[ 9 ] ] ^ Configuration::Mul11[ this->state[ 10 ] ] ^ Configuration::Mul13[ this->state[ 11 ] ] );
         kucpTemp[ 10 ] = static_cast< uint8_t >( Configuration::Mul13[ this->state[ 8 ] ] ^ Configuration::Mul9[ this->state[ 9 ] ] ^ Configuration::Mul14[ this->state[ 10 ] ] ^ Configuration::Mul11[ this->state[ 11 ] ] );
         kucpTemp[ 11 ] = static_cast< uint8_t >( Configuration::Mul11[ this->state[ 8 ] ] ^ Configuration::Mul13[ this->state[ 9 ] ] ^ Configuration::Mul9[ this->state[ 10 ] ] ^ Configuration::Mul14[ this->state[ 11 ] ] );

         kucpTemp[ 12 ] = static_cast< uint8_t >( Configuration::Mul14[ this->state[ 12 ] ] ^ Configuration::Mul11[ this->state[ 13 ] ] ^ Configuration::Mul13[ this->state[ 14 ] ] ^ Configuration::Mul9[ this->state[ 15 ] ] );
         kucpTemp[ 13 ] = static_cast< uint8_t >( Configuration::Mul9[ this->state[ 12 ] ] ^ Configuration::Mul14[ this->state[ 13 ] ] ^ Configuration::Mul11[ this->state[ 14 ] ] ^ Configuration::Mul13[ this->state[ 15 ] ] );
         kucpTemp[ 14 ] = static_cast< uint8_t >( Configuration::Mul13[ this->state[ 12 ] ] ^ Configuration::Mul9[ this->state[ 13 ] ] ^ Configuration::Mul14[ this->state[ 14 ] ] ^ Configuration::Mul11[ this->state[ 15 ] ] );
         kucpTemp[ 15 ] = static_cast< uint8_t >( Configuration::Mul11[ this->state[ 12 ] ] ^ Configuration::Mul13[ this->state[ 13 ] ] ^ Configuration::Mul9[ this->state[ 14 ] ] ^ Configuration::Mul14[ this->state[ 15 ] ] );

         for( kuiI = 0; kuiI < Configuration::KeySize; kuiI++ )
         {
            this->state[ kuiI ] = kucpTemp[ kuiI ];
         }
      }
   }
}

