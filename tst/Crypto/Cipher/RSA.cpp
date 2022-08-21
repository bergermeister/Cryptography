// Google Test Include
#include <gtest/gtest.h>

// Crypto Includes
#include <Crypto/Cipher/ICipher.h>
#include <Crypto/Cipher/RSA.h>
/*
TEST( Communication, RSA )
{
   const int64_t xlPlaintext[ 7 ] = { 65, 3232, 1, 2314, 7919, 6691, 7919 * 6691 };
   int64_t       klCiphertext[ 7 ];
   int64_t       klPlaintext[ 7 ];

   Crypto::Cipher::ICipher* kopCipher = new Crypto::Cipher::RSA( );
   Crypto::Cipher::RSA*     kopRSA = static_cast< Crypto::Cipher::RSA* >( kopCipher );           

   /// -# Choose two distinct prime numbers
   //kopRSA->Initialize( 7919, 6691, 15 );
   kopRSA->Initialize( 61, 53, 3 );

   /// -# Encryption funcition c(m)=m^e mod n
   kopCipher->Encrypt( reinterpret_cast< const uint8_t* >( &xlPlaintext ), 
                       reinterpret_cast< uint8_t* >( &klCiphertext ), 8 * 7 );

   /// -# Deryption function m(c)=c^kiD mod n
   kopCipher->Decrypt( ( const uint8_t* )&klCiphertext, ( uint8_t* )&klPlaintext, 8 * 7 );

   delete kopCipher;

   for( uint32_t word = 0; word < 7; word++ )
   {
      ASSERT_EQ( xlPlaintext[ word ], klPlaintext[ word ] );
   }
}
*/
