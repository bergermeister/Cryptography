#include <pch.h>
#include <CppUnitTest.h>
#include <Types.h>
#include <Communication/Session.h>
#include <Communication/Messages/EstablishSession.h>

namespace CryptoTest
{
   namespace NCommunication
   {
      using namespace Microsoft::VisualStudio::CppUnitTestFramework;
      using namespace GNCrypto;
      using namespace GNCrypto::NCommunication;

      TEST_CLASS( TuSession )
      {
      public:
         TEST_METHOD( MEstablish )
         {
            const Tc8  xcpTestStr[ ] = "SENDER: Alice\r\nRECIPIENT: BOB\r\nSUBJECT: Test Message";
            const Tu32 xuiTestLen    = 52;
            const Tu64 xulpPKeyAlice[ ] = { 4, 5, 6, 7, 8 };
            const Tu64 xulpPKeyBob[ ] = { 3, 4, 5, 6, 7 };
            Tc8        kcpCiphertext[ 64 ];
            Tc8        kcpPlaintext[ 64 ];
            TcSession  koAlice( xulpPKeyAlice );
            TcSession  koBob( xulpPKeyBob );
            NMessages::TcEstablishSession koMsgAlice;
            NMessages::TcEstablishSession koMsgBob;

            /// @par Process Design Langauge
            /// -# Alice is initialized with Private Keys
            /// -# Bob is initialized with Private Keys

            /// -# Alice creates an Establish Session Request message
            koMsgAlice = koAlice.MRequest( );

            /// -# Alice sends Establish Session Request message to Bob
            /// -# Bob:
            ///   -# Processes received Establish Session Request
            ///   -# Creates his Shared Secret
            ///   -# Generates Establish Session Acknowledge message
            koMsgBob = koBob.MEstablish( koMsgAlice, false );

            /// -#  Bob sends Establish Session Acknowledge message to Alice
            /// -# Alice:
            ///   -# Process received Establish Session Acknowledge
            ///   -# Creates her Shared Secret
            ( void )koAlice.MEstablish( koMsgBob, false );

            koAlice.MEncrypt( reinterpret_cast< const Tu8* >( xcpTestStr ), reinterpret_cast< Tu8* >( kcpCiphertext ), xuiTestLen );
            koBob.MDecrypt( reinterpret_cast< const Tu8* >( kcpCiphertext ), reinterpret_cast< Tu8* >( kcpPlaintext ), 64 );

            Assert::AreEqual( xcpTestStr, kcpPlaintext, L"ERROR: Plaintext Mismatch" );
         }

         TEST_METHOD( MDynamicSBox )
         {
            const Tc8  xcpTestStr[ ] = "SENDER: Alice\r\nRECIPIENT: BOB\r\nSUBJECT: Test Message";
            const Tu32 xuiTestLen = 52;
            const Tu64 xulpPKeyAlice[ ] = { 4, 5, 6, 7, 8 };
            const Tu64 xulpPKeyBob[ ] = { 3, 4, 5, 6, 7 };
            Tc8        kcpCiphertext[ 64 ];
            Tc8        kcpPlaintext[ 64 ];
            TcSession  koAlice( xulpPKeyAlice );
            TcSession  koBob( xulpPKeyBob );
            NMessages::TcEstablishSession koMsgAlice;
            NMessages::TcEstablishSession koMsgBob;

            /// @par Process Design Langauge
            /// -# Alice is initialized with Private Keys
            /// -# Bob is initialized with Private Keys

            /// -# Alice creates an Establish Session Request message
            koMsgAlice = koAlice.MRequest( );

            /// -# Alice sends Establish Session Request message to Bob
            /// -# Bob:
            ///   -# Processes received Establish Session Request
            ///   -# Creates his Shared Secret
            ///   -# Generates Establish Session Acknowledge message
            koMsgBob = koBob.MEstablish( koMsgAlice, true );

            /// -#  Bob sends Establish Session Acknowledge message to Alice
            /// -# Alice:
            ///   -# Process received Establish Session Acknowledge
            ///   -# Creates her Shared Secret
            (void )koAlice.MEstablish( koMsgBob, true );

            koAlice.MEncrypt( reinterpret_cast< const Tu8* >( xcpTestStr ), reinterpret_cast< Tu8* >( kcpCiphertext ), xuiTestLen );
            koBob.MDecrypt( reinterpret_cast< const Tu8* >( kcpCiphertext ), reinterpret_cast< Tu8* >( kcpPlaintext ), 64 );

            Assert::AreEqual( xcpTestStr, kcpPlaintext, L"ERROR: Plaintext Mismatch" );
         }

         TEST_METHOD( MVector )
         {
            const Tu8 xucpPlaintext[ ] =
            {
               0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
            };
            const Tu32 xuiTestLen = 52;
            const Tu64 xulpPKeyAlice[ ] = { 4, 5, 6, 7, 8 };
            const Tu64 xulpPKeyBob[ ] = { 3, 4, 5, 6, 7 };
            Tc8        kcpCiphertext[ 16 ];
            Tc8        kcpPlaintext[ 16 ];
            TcSession  koAlice( xulpPKeyAlice );
            TcSession  koBob( xulpPKeyBob );
            NMessages::TcEstablishSession koMsgAlice;
            NMessages::TcEstablishSession koMsgBob;

            /// @par Process Design Langauge
            /// -# Alice is initialized with Private Keys
            /// -# Bob is initialized with Private Keys

            /// -# Alice creates an Establish Session Request message
            koMsgAlice = koAlice.MRequest( );

            /// -# Alice sends Establish Session Request message to Bob
            /// -# Bob:
            ///   -# Processes received Establish Session Request
            ///   -# Creates his Shared Secret
            ///   -# Generates Establish Session Acknowledge message
            koMsgBob = koBob.MEstablish( koMsgAlice, true );

            /// -#  Bob sends Establish Session Acknowledge message to Alice
            /// -# Alice:
            ///   -# Process received Establish Session Acknowledge
            ///   -# Creates her Shared Secret
            ( void )koAlice.MEstablish( koMsgBob, true );

            koAlice.MEncrypt( xucpPlaintext, reinterpret_cast< Tu8* >( kcpCiphertext ), xuiTestLen );
            koBob.MDecrypt( reinterpret_cast< const Tu8* >( kcpCiphertext ), reinterpret_cast< Tu8* >( kcpPlaintext ), 16 );

            Assert::AreEqual( reinterpret_cast< const Tc8* >( xucpPlaintext ), kcpPlaintext, L"ERROR: Plaintext Mismatch" );
         }
      };
   }
}