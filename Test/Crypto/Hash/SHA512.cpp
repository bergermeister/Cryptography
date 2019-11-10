#include <pch.h>
#include <CppUnitTest.h>
#include <Types.h>
#include <Hash/SHA512.h>

namespace CryptoTest
{
   using namespace Microsoft::VisualStudio::CppUnitTestFramework;
   using namespace GNCrypto;
   using namespace GNCrypto::NHash;
   namespace NHash
   {
      TEST_CLASS( TuSHA512 )
      {
      public:
         TEST_METHOD( MVector1 )
         {
            const Tu64 xulpExpected[ ] =
            {
               0xddaf35a193617aba, 0xcc417349ae204131, 0x12e6fa4e89a97ea2, 0x0a9eeee64b55d39a,
               0x2192992a274fc1a8, 0x36ba3c23a3feebbd, 0x454d4423643ce80e, 0x2a9ac94fa54ca49f
            };
            const Tu8  xucpMsg[ ] = "abc";
            const Tu32 xuiBytes = 3;

            TcSHA512    koSHA;
            Tu32        kuiIdx;
            const Tu64* kulpDigest;

            /// -# Calculate SHA
            koSHA.MInitialize( );
            koSHA.MProcess( xucpMsg, xuiBytes );
            koSHA.MFinalize( );

            /// -# Obtain Digest
            kulpDigest = reinterpret_cast< const Tu64* >( koSHA.MDigest( ) );

            for( kuiIdx = 0; kuiIdx < ( TcSHA512::XuiLength / sizeof( Tu64 ) ); kuiIdx++ )
            {
               Assert::AreEqual( xulpExpected[ kuiIdx ], kulpDigest[ kuiIdx ], L"ERROR: Digest Byte Mismatch" );
            }
         }
      };
   }
}

