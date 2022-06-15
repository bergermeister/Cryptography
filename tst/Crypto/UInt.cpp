// Precompiled Header Include
#include <Crypto/pch.h>

namespace CryptoTest
{
   using namespace Microsoft::VisualStudio::CppUnitTestFramework;

   TEST_CLASS( UIntUT )
   {
   public:
      TEST_METHOD( Addition )
      {
         using UInt256 = Crypto::UInt< 256 >;
         static constexpr uint32_t maxValue = 0x11111111;
         UInt256 value;
         size_t index;
         
         value = 0;
         for( index = 0; index < maxValue; index++ )
         {
            value += 1;
         }
         Assert::AreEqual( maxValue,
                           *reinterpret_cast< const uint32_t* >( value.Bytes( ) ) );
      }

      TEST_METHOD( Subtraction )
      {
         using UInt256 = Crypto::UInt< 256 >;
         static constexpr uint32_t maxValue = 0x11111111;
         UInt256 value;
         size_t index;

         value = maxValue;
         for( index = 0; index < maxValue; index++ )
         {
            value -= 1;
            
            /* Assert::AreEqual( static_cast< uint32_t >( maxValue - ( index + 1 ) ),
                              *reinterpret_cast< const uint32_t* >( value.Bytes( ) ) ); */
         }
         Assert::AreEqual( static_cast< const uint32_t >( 0 ), 
                           *reinterpret_cast< const uint32_t* >( value.Bytes( ) ) );

         value = maxValue;
         for( index = 0; index <= maxValue; index++ )
         {
            value -= 1;
         }
         Assert::AreEqual( static_cast< const uint32_t >( 0xFFFFFFFF ),
                           *reinterpret_cast< const uint32_t* >( value.Bytes( ) ) );
      }

      TEST_METHOD( Multiplication )
      {
         using UInt256 = Crypto::UInt< 256 >;
         static constexpr uint32_t valueA = 0x000000FF; //      255
         static constexpr uint32_t valueB = 0x0000FFFF; //    65535
         static constexpr uint32_t valueE = 0x00FEFF01; // 16711425
         UInt256 value;

         value = valueA;
         value *= valueB;
         Assert::AreEqual( valueE, *reinterpret_cast< uint32_t* >( value.Bytes( ) ) );

         value = valueB;
         value *= valueA;
         Assert::AreEqual( valueE, *reinterpret_cast< uint32_t* >( value.Bytes( ) ) );
      }

      TEST_METHOD( Division )
      {
         using UInt256 = Crypto::UInt< 256 >;
         static constexpr uint64_t valueA = 0x0123456789ABCDEF;
         static constexpr uint64_t valueB = 0x0000000000001234; //    65535
         static constexpr uint64_t valueE = 0x000010004C016906;

         UInt256 value;

         value = valueA;
         value /= valueB;
         Assert::AreEqual( valueE, *reinterpret_cast< uint64_t* >( value.Bytes( ) ) );

         value = valueB;
         value *= valueA;
         Assert::AreEqual( static_cast< uint64_t >( 0 ), *reinterpret_cast< uint64_t* >( value.Bytes( ) ) );
      }
   };
}
