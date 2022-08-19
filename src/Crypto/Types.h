/**
 * @file
 */
#ifndef Crypto_Types_h
#define Crypto_Types_h

// StdLib Includes
#include <cstdint>   // base types (uint32_t, etc...)
#include <cstring>
#include <string>    // memcpy

namespace Crypto
{
   static constexpr size_t BitsPerByte = 8;

   /**
    * @brief
    * Rotate Left Operation
    *
    * @details
    * @par
    * This method performs the Rotate left (circular left shift) operation, where x is a w-bit word and n is an integer
    * with 0 <= n < w, is defined by ROTL( x, n, w )=( x << n ) | ( x >> ( w - n ) ).
    *
    * @return
    * This method returns the 64-bit word rotated left.
    *
    * @param aoX     [in] W-bit word to be operated on
    * @param aoN     [in] Integer with 0 <= N <= W
    */
   template< class T >inline T ROTL( const T aoX, const T aoN )
   {
      return( ( aoX << aoN ) | ( aoX >> ( ( sizeof( T ) * BitsPerByte ) - aoN ) ) );
   }

   /**
    * @brief
    * Rotate Right Operation
    *
    * @details
    * @par
    * This method performs the Rotate right (circular right shift) operation, where x is a w-bit word and n is an integer
    * with 0 <= n < w, is defined by ROTR( x, n, w )=( x >> n ) | ( x << ( w - n ) ).
    *
    * @return
    * This method returns the 64-bit word rotated right.
    *
    * @param aoX     [in] W-bit word to be operated on
    * @param aoN     [in] Integer with 0 <= N <= W
    */
   template< class T > inline T ROTR( const T aoX, const T aoN )
   {
      return( ( aoX >> aoN ) | ( aoX << ( ( sizeof( T ) * BitsPerByte ) - aoN ) ) );
   }

   /**
    * This method performs the Rotate shift operation, where x is a w-bit word and n is an integer with 0 <= n < w, is
    * defined by ( x, n )=( x >> n ).
    *
    * @return
    * This method returns the 64-bit word rotated left.
    *
    * @param[in] aoX    W-bit word to be operated on
    * @param[in] aoN    Integer with 0 <= N <= W
    */
   template< class T > inline T SHR( const T aoX, const T aoN )
   {
      return( aoX >> aoN );
   }

   /**
    * Choose Operation
    */
   template< class T > inline T Choose( const T aoX, const T aoY, const T aoZ )
   {
      return( ( aoX & aoY ) ^ ( ~aoX & aoZ ) );
   }

   /**
    * Majority Operation
    */
   template< class T > inline T Majority( const T aoX, const T aoY, const T aoZ )
   {
      return( ( aoX & aoY ) ^ ( aoX & aoZ ) ^ ( aoY & aoZ ) );
   }
}

#endif

