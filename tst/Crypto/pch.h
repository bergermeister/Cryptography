// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// Windows CPP Unit Test Framework
#include <CppUnitTest.h>

// Standard Libraries
#include <vector>

// External Support Libraries
#include <Crypto/Math/galois.h>

//Crpyto Library Includes
#include <Crypto/Types.h>
#include <Crypto/UInt.h>
#include <Crypto/Math/GCD.h>
#include <Crypto/Math/Prime.h>
#include <Crypto/Hash/SHA512.h>
#include <Crypto/Cipher/RSA.h>
#include <Crypto/KeyExchange/PublicKey.h>
#include <Crypto/KeyExchange/DiffieHellman.h>
#include <Crypto/AES/Configuration.h>
#include <Crypto/AES/Decryptor.h>
#include <Crypto/AES/Encryptor.h>
#include <Crypto/Communication/Session.h>
#include <Crypto/Communication/Messages/EstablishSession.h>

#endif //PCH_H
