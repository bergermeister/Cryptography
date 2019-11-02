/**
 * @file
 * @brief
 * Generic Secure Hash Algorithm Package
 *
 * @details
 * @par
 * This package provides the Secure Hash Algorithm base class.
 */
#include <Types.h>
#include <Hash/Algorithm.h>
#include <Hash/SHA.h>

using namespace GNCrypto;
using namespace GNCrypto::NHash;

TcSHA::TcSHA( const Tu8* aucpDigest ) : TcAlgorithm( aucpDigest )
{
   // Nothing to construct
}

TcSHA::TcSHA( const TcSHA& aorSHA ) : TcAlgorithm( aorSHA )
{
   // Call assignment operator
   *this = aorSHA;
}

TcSHA::~TcSHA( void )
{
   // Nothing to destruct
}

TcSHA& TcSHA::operator=( const TcSHA& aorSHA )
{
   // Prevent self-assignment
   if( this != &aorSHA )
   {

   }

   return( *this );
}

