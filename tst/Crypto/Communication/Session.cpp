// Google Test Include
#include <gtest/gtest.h>

// Crypto Includes
#include <Crypto/Communication/Session.h>

using namespace Crypto::Communication;

TEST( Session, Establish )
{
   const char  xcpTestStr[ ] = "SENDER: Alice\r\nRECIPIENT: BOB\r\nSUBJECT: Test Message";
   const uint32_t xuiTestLen    = 52;
   const uint64_t xulpPKeyAlice[ ] = { 4, 5, 6, 7, 8 };
   const uint64_t xulpPKeyBob[ ] = { 3, 4, 5, 6, 7 };
   char        kcpCiphertext[ 64 ];
   char        kcpPlaintext[ 64 ];
   Session  koAlice( xulpPKeyAlice );
   Session  koBob( xulpPKeyBob );
   Messages::EstablishSession koMsgAlice;
   Messages::EstablishSession koMsgBob;

   /// @par Process Design Langauge
   /// -# Alice is initialized with Private Keys
   /// -# Bob is initialized with Private Keys

   /// -# Alice creates an Establish Session Request message
   koMsgAlice = koAlice.Request( );

   /// -# Alice sends Establish Session Request message to Bob
   /// -# Bob:
   ///   -# Processes received Establish Session Request
   ///   -# Creates his Shared Secret
   ///   -# Generates Establish Session Acknowledge message
   koMsgBob = koBob.Establish( koMsgAlice, false );

   /// -#  Bob sends Establish Session Acknowledge message to Alice
   /// -# Alice:
   ///   -# Process received Establish Session Acknowledge
   ///   -# Creates her Shared Secret
   ( void )koAlice.Establish( koMsgBob, false );

   koAlice.Encrypt( reinterpret_cast< const uint8_t* >( xcpTestStr ), reinterpret_cast< uint8_t* >( kcpCiphertext ), xuiTestLen );
   koBob.Decrypt( reinterpret_cast< const uint8_t* >( kcpCiphertext ), reinterpret_cast< uint8_t* >( kcpPlaintext ), 64 );

   ASSERT_STREQ( xcpTestStr, kcpPlaintext );
}

TEST( Session, DefaultSBox )
{
   const char  xcpTestStr[ ] = "John Doe\n12345 Random Rd.\nSomeTown, AA 67890\0\0\0\0\0\0\0\0";
   const uint32_t xuiTestLen = 80;
   const uint32_t xuiCiphLen = xuiTestLen + ( xuiTestLen % 16 );
   const uint64_t xulpPKeyAlice[ ] = { 4, 5, 6, 7, 8 };
   const uint64_t xulpPKeyBob[ ] = { 3, 4, 5, 6, 7 };
   char        kcpCiphertext[ xuiCiphLen ];
   char        kcpPlaintext[ xuiCiphLen ];
   Session  koAlice( xulpPKeyAlice );
   Session  koBob( xulpPKeyBob );
   Messages::EstablishSession koMsgAlice;
   Messages::EstablishSession koMsgBob;

   /// @par Process Design Langauge
   /// -# Alice is initialized with Private Keys
   /// -# Bob is initialized with Private Keys

   /// -# Alice creates an Establish Session Request message
   koMsgAlice = koAlice.Request( );

   /// -# Alice sends Establish Session Request message to Bob
   /// -# Bob:
   ///   -# Processes received Establish Session Request
   ///   -# Creates his Shared Secret
   ///   -# Generates Establish Session Acknowledge message
   koMsgBob = koBob.Establish( koMsgAlice, false );

   /// -#  Bob sends Establish Session Acknowledge message to Alice
   /// -# Alice:
   ///   -# Process received Establish Session Acknowledge
   ///   -# Creates her Shared Secret
   (void )koAlice.Establish( koMsgBob, false );

   koAlice.Encrypt( reinterpret_cast< const uint8_t* >( xcpTestStr ), reinterpret_cast< uint8_t* >( kcpCiphertext ), xuiTestLen );
   koBob.Decrypt( reinterpret_cast< const uint8_t* >( kcpCiphertext ), reinterpret_cast< uint8_t* >( kcpPlaintext ), xuiCiphLen );

   ASSERT_STREQ( xcpTestStr, kcpPlaintext );
}

TEST( Session, DynamicSBox )
{
   const uint8_t xucpKey[ ] =
   {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
   };
   const uint8_t xucpPlaintext[ ] =
   {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
   };
   const uint32_t xuiTestLen = 16;
   const uint64_t xulpPKeyAlice[ ] = { 4, 5, 6, 7, 8 };
   const uint64_t xulpPKeyBob[ ] = { 3, 4, 5, 6, 7 };
   char        kcpCiphertext[ 16 ];
   char        kcpPlaintext[ 16 ];
   Session  koAlice( xulpPKeyAlice );
   Session  koBob( xulpPKeyBob );
   Messages::EstablishSession koMsgAlice;
   Messages::EstablishSession koMsgBob;

   /// @par Process Design Langauge
   /// -# Alice is initialized with Private Keys
   /// -# Bob is initialized with Private Keys

   /// -# Alice creates an Establish Session Request message
   koMsgAlice = koAlice.Request( );

   /// -# Alice sends Establish Session Request message to Bob
   /// -# Bob:
   ///   -# Processes received Establish Session Request
   ///   -# Creates his Shared Secret
   ///   -# Generates Establish Session Acknowledge message
   koMsgBob = koBob.Establish( koMsgAlice, true );

   /// -#  Bob sends Establish Session Acknowledge message to Alice
   /// -# Alice:
   ///   -# Process received Establish Session Acknowledge
   ///   -# Creates her Shared Secret
   ( void )koAlice.Establish( koMsgBob, true );

   /// -# Override Alice and Bob's AES Configuration's Key with the AES Test Vector Key
   koAlice.Configuration( ).ExpandKey( xucpKey );
   koBob.Configuration( ).ExpandKey( xucpKey );

   koAlice.Encrypt( xucpPlaintext, reinterpret_cast< uint8_t* >( kcpCiphertext ), xuiTestLen );
   koBob.Decrypt( reinterpret_cast< const uint8_t* >( kcpCiphertext ), reinterpret_cast< uint8_t* >( kcpPlaintext ), 16 );

   ASSERT_STREQ( reinterpret_cast< const char* >( xucpPlaintext ), kcpPlaintext );
}

