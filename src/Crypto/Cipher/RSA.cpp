// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Cipher/ICipher.h>
#include <Crypto/Cipher/RSA.h>
#include <Crypto/Math/GCD.h>

// StdLib Includes
#include <vector>

namespace Crypto
{
   namespace Cipher
   {
      /**
       * 
       * @param[in] P 
       * @param[in] Q 
       * @param[in] I 
       * @return This method returns nothing.
       */
      void RSA::Initialize( const int64_t P, const int64_t Q, int64_t I )
      {
         int64_t y;
         std::vector< std::pair< int64_t, int64_t > > Inverses;
         
         /// @par Process Design Language
         /// -# Compute n = pq
         this->n = P * Q;

         /// -# Compute the Carmichael's totient function of the product as Y(N)=lcm(p - 1, q - 1)
         y = Crypto::NMath::MLCM( P - 1, Q - 1 );

         /// -# Choose any number 1 < e < Y that is coprime to 780
         Inverses = Crypto::NMath::MMultiplicativeInverses( y );
         if( I >= static_cast< int64_t >( Inverses.size( ) ) )
         {
            I = Inverses.size( ) / 2;
         }
         this->e = Inverses[ I ].first;

         /// -# Compute d, the modular multiplicative inverse of e mod Y 
         this->d = Inverses[ 3 ].second;
      }

      /**
       * 
       * @return This method returns nothing.
       * 
       * @param[in]  Plaintext 
       * @param[out] Ciphertext 
       * @param[in]  Bytes 
       */
      void RSA::Encrypt( const uint8_t* Plaintext, uint8_t* Ciphertext, const size_t Bytes )
      {
         size_t remaining = Bytes;
         size_t bytes;
         int64_t word;
         int64_t value;
         int64_t index;
         const int64_t* plaintext  = reinterpret_cast< const int64_t* >( Plaintext );
         int64_t* ciphertext = reinterpret_cast< int64_t* >( Ciphertext );

         while( remaining > 0 )
         {
            bytes = remaining;
            if( remaining > sizeof( int64_t ) )
            {
               bytes = sizeof( int64_t );
            }

            value = 0;
            std::memcpy( reinterpret_cast< void* >( &value ), reinterpret_cast< const void* >( plaintext ), bytes );
            word = 1;
            for( index = 0; index < this->e; index++ )
            {
               word *= value;
               word %= this->n;
            }
            while( word < 0 )
            {
               word += this->n;
            }
            std::memcpy( reinterpret_cast< void* >( ciphertext ), reinterpret_cast< const void* >( &word ), bytes );

            remaining -= sizeof( size_t );
            plaintext++;
            ciphertext++;
         }
      }

      /**
       * 
       * 
       * @return This method returns nothing.
       * 
       * @param[in]  Ciphertext 
       * @param[out] Plaintext 
       * @param[in]  Bytes 
       */
      void RSA::Decrypt( const uint8_t* Ciphertext, uint8_t* Plaintext, const size_t Bytes )
      {
         size_t remaining = Bytes;
         size_t bytes;
         int64_t word;
         int64_t value;
         int64_t index;
         int64_t*       plaintext  = reinterpret_cast< int64_t* >( Plaintext );
         const int64_t* ciphertext = reinterpret_cast< const int64_t* >( Ciphertext );

         while( remaining > 0 )
         {
            bytes = remaining;
            if( remaining > sizeof( int64_t ) )
            {
               bytes = sizeof( int64_t );
            }

            value = 0;
            std::memcpy( reinterpret_cast< void* >( &value ), reinterpret_cast< const void* >( ciphertext ), bytes );
            word = 1;
            for( index = 0; index < this->d; index++ )
            {
               word *= value;
               word %= this->n;
            }
            while( word < 0 )
            {
               word += this->n;
            }
            std::memcpy( reinterpret_cast< void* >( plaintext ), reinterpret_cast< const void* >( &word ), bytes );

            remaining -= bytes;
            plaintext++;
            ciphertext++;
         }
      }
   }
}

