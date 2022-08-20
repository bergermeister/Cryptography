/**
 * @file
 * This package provides the 512-Bit Secure Hash Algorithm (SHA-512) class.
 */
#ifndef Crypto_Hash_SHA512_h
#define Crypto_Hash_SHA512_h

// Crypto Includes
#include <Crypto/Types.h>
#include <Crypto/Hash/Algorithm.h>
#include <Crypto/Hash/SHA.h>

 /// Namespace containing Cryptographic functionality
namespace Crypto
{
   /// Namespace containing Hashing algorithms
   namespace Hash
   {
      /** 
       * 512-bit Secure Hashing Algorithm (SHA-512)
       */
      class SHA512 : public SHA
      {
      public:        // Public Attributes
         static const size_t Length = 64;   ///< Length of Hash in bytes

      private:       // Private Attributes
         static const uint32_t constantCount    = 80;                         ///< 
         static const uint32_t blockSize = 128;                               ///< Block size in bytes 
         static const uint32_t lengthInWords = Length / sizeof( uint64_t );   ///< Length of digest in 64-bit words
         static const uint32_t padMax      = 112;
         static const uint32_t padEnd      = 123;
         static const uint64_t constant[ constantCount ];                     ///< 
         static const uint64_t defaultHash[ lengthInWords ];                  ///< 

         uint64_t hash[ lengthInWords ];                                   ///< Calculated Hash 

      public:        // Public Methods
         SHA512( void );
         SHA512( const SHA512& aorSHA );
         ~SHA512( void );
         SHA512& operator=( const SHA512& aorSHA );

         void Initialize( void );
         void Process( const uint8_t* aucpData, const size_t auiLength );
         void Finalize( void );

         using Algorithm::Digest;
         using Algorithm::BytesDigested;

      private:       // Private Methods
         void processBlock( const uint8_t* aucpBlock );

         inline uint64_t sig1( const uint64_t aulX )
         {
            return( ROTR< uint64_t >( aulX, 28 ) ^ ROTR< uint64_t >( aulX, 34 ) ^ ROTR< uint64_t >( aulX, 39 ) );
         }

         inline uint64_t sig2( const uint64_t aulX )
         {
            return( ROTR< uint64_t >( aulX, 14 ) ^ ROTR< uint64_t >( aulX, 18 ) ^ ROTR< uint64_t >( aulX, 41 ) );
         }

         inline uint64_t sig3( const uint64_t aulX )
         {
            return( ROTR< uint64_t >( aulX, 1 ) ^ ROTR< uint64_t >( aulX, 8 ) ^ SHR< uint64_t >( aulX, 7 ) );
         }

         inline uint64_t sig4( const uint64_t aulX )
         {
            return( ROTR< uint64_t >( aulX, 19 ) ^ ROTR< uint64_t >( aulX, 61 ) ^ SHR< uint64_t >( aulX, 6 ) );
         }
      };
   }
}

#endif

