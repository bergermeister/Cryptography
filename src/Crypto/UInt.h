#ifndef Crypto_Math_Numebr_h
#define Crypto_Math_UInt_h

// Crypto Includes
#include <Crypto/Types.h>

namespace Crypto
{
   template< size_t Bits > class UInt
   {
   public:     // Public Attributes
      /// Number bytes used to store the value
      static constexpr size_t ByteCount = ( Bits + BitsPerByte - 1 ) / BitsPerByte; 
         
   private:    // Private Attributes
      uint8_t data[ ByteCount ];    ///< Array of bytes used to store the unsigned integer

   public:     // Public Methods
      /**
       * This method constructs an unsigned integer
       * 
       * @return
       * This method returns nothing.
       * 
       * @param None
       */
      UInt( void ) = default;

      /**
       * This method retrieves the UInt as an array of bytes.
       *  
       * @return 
       * This method returns the UInt as an array of bytes
       * 
       * @param None
       */
      uint8_t* Bytes( void )
      {
         return( this->data );
      }

      /**
       * 
       * @return 
       * 
       * 
       * @tparam[in] T 
       * @param[in]  B 
       */
      template< class T > UInt& operator=( const T& B )
      {
         /// @par Process Design Language
         /// -# Ensure this object is not being assigned to itself
         if( reinterpret_cast< uintptr_t >( this ) != reinterpret_cast< uintptr_t >( &B ) )
         {
            /// -# Clear the storage array to 0
            std::memset( reinterpret_cast< void* >( this->data ), 0, ByteCount );

            /// -# Copy the contents of the given object into this object
            std::memcpy( reinterpret_cast< void* >( this->data ),
                         reinterpret_cast< const void* >( &B ),
                         sizeof( T ) );
         }

         /// -# Return a reference to this object
         return( *this );
      }

      /**
       * 
       * 
       * @return 
       * 
       * 
       * @tparam[in] T 
       * @param[in] B 
       */
      template< class T > UInt operator+( const T& B )
      {
         size_t byte;
         uint16_t result = 0;
         UInt C;
         const uint8_t* b = reinterpret_cast< const uint8_t* >( &B );

         for( byte = 0; byte < ByteCount; byte++ )
         {
            result = static< uint16_t >( this->data[ byte ] + b[ byte ] + static_cast< uint8_t >( result ) );
            C.data[ byte ] = static_cast< uint8_t >( result );
            result = ( result >> static_cast< uint16_t >( BitsPerByte ) ) & 0x00FF;
         }

         return( C );
      }

      /**
       * 
       * 
       * @return 
       * 
       * 
       * @tparam[in] T 
       * @param[in]  B 
      */
      template< class T > UInt& operator+=( const T& B )
      {
         size_t byte;
         uint16_t result = 0;
         const uint8_t* b = reinterpret_cast< const uint8_t* >( &B );

         for( byte = 0; byte < ByteCount; byte++ )
         {
            result = static_cast< uint16_t >( 
               this->data[ byte ] + b[ byte ] + static_cast< uint8_t >( result ) );
            this->data[ byte ] = static_cast< uint8_t >( result );
            result = ( result >> static_cast< uint16_t >( BitsPerByte ) ) & 0x00FF;
         }

         return( *this );
      }

      template< class T > UInt operator-( const T& B )
      {
         size_t byte;
         uint16_t result;
         const uint8_t* b = reinterpret_cast< const uint8_t* >( &B );
         UInt C;
         for( byte = 0; byte < ByteCount; byte++ )
         {
            result = 0;
            if( this->data[ byte ] < b[ byte ] )
            {
               result = 256;
            }
            result = ( result + static_cast< uint16_t >( this->data[ byte ] ) ) - static_cast< uint16_t >( b[ byte ] );
            C.data[ byte ] = static_cast< uint8_t >( result & 0x00FF );
         }

         return( C );
      }

      template< class T > UInt operator-=( const T& B )
      {
         size_t byte;
         uint16_t difference;
         uint16_t minuend;       // Number to be subtracted from
         uint16_t subtrahend;    // Number to be subtracted
         uint16_t carry = 0;
         const uint8_t* b = reinterpret_cast< const uint8_t* >( &B );
         for( byte = 0; byte < sizeof( T ); byte++ )
         {
            minuend = static_cast< uint16_t >( this->data[ byte ] );
            subtrahend = static_cast< uint16_t >( b[ byte ] ) + carry;
            if( minuend < subtrahend )
            {
               carry = 1;
            }
            else
            {
               carry = 0;
            }
            difference = ( ( 256 * carry ) + minuend ) - subtrahend;
            this->data[ byte ] = static_cast< uint8_t >( difference & 0x00FF );
         }

         for( ; ( byte < ByteCount ) && ( carry == 1 ); byte++ )
         {
            minuend = static_cast< uint16_t >( this->data[ byte ] );
            subtrahend = carry;
            if( minuend < subtrahend )
            {
               carry = 1;
            }
            else
            {
               carry = 0;
            }
            difference = ( ( 256 * carry ) + minuend ) - subtrahend;
            this->data[ byte ] = static_cast< uint8_t >( difference & 0x00FF );
         }

         if( carry != 0 )
         {
            for( byte = 0; byte < ByteCount; byte++ )
            {
               this->data[ byte ] = ~this->data[ byte ];
            }
         }

         return( *this );
      }

      UInt operator*( const UInt& B )
      {

      }

      UInt operator/( const UInt& B )
      {

      }

      UInt operator%( const UInt& B )
      {

      }
   };
}

#endif
