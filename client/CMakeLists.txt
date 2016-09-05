# Copyright (c) 2014-2016, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

############# build workarounds for trezor-crypto (errors)
add_definitions(-DED25519_CUSTOMRANDOM=1)
add_definitions(-DED25519_CUSTOMHASH=1)
include_directories(trezor-crypto/ed25519-donna)
set(trezor_crypto_sources 
	trezor-crypto/aescrypt.c 
	trezor-crypto/aeskey.c 
	trezor-crypto/aes_modes.c 
	trezor-crypto/aestab.c 
	trezor-crypto/base58.c 
	trezor-crypto/bignum.c 
	trezor-crypto/bip32.c 
	trezor-crypto/bip39.c 
	trezor-crypto/ecdsa.c 
	trezor-crypto/hmac.c 
	trezor-crypto/pbkdf2.c 
	trezor-crypto/rand.c 
	trezor-crypto/ripemd160.c 
	trezor-crypto/secp256k1.c 
	trezor-crypto/nist256p1.c
	trezor-crypto/pbkdf2.c
	trezor-crypto/sha2.c
	trezor-crypto/curves.c
	trezor-crypto/ed25519-donna/ed25519.c)

set_source_files_properties(${trezor_crypto_sources} 
	PROPERTIES 
	COMPILE_FLAGS 
	"-Wno-attributes -Wno-error -Wno-unused-variable -Wno-vla -Wno-sequence-point -Wno-strict-prototypes")

add_library(trezorcrypto STATIC ${trezor_crypto_sources})


############# build workarounds for hidapi (errors)
include_directories(hidapi/hidapi)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  	add_subdirectory(hidapi/mac)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  	add_subdirectory(hidapi/windows)
else()
  	message(STATUS "Using HIDAPI unix build")
  	add_library(hidapi hidapi/libusb/hid.c)
	set_source_files_properties(hidapi/libusb/hid.c PROPERTIES COMPILE_FLAGS "-Wno-error")
	find_package(PkgConfig)
	pkg_check_modules(LIBUSB_1 REQUIRED libusb-1.0)
	include_directories(${LIBUSB_1_INCLUDE_DIRS})
	target_link_libraries(hidapi ${LIBUSB_1_LIBRARIES} rt)
endif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

############# simple trezor wallet/interface library
include_directories(../../crypto)
include_directories(trezor-crypto)
include_directories(hidapi/hidapi)
include_directories(protobuf-c)
include_directories(protobuf-c/protobuf-c)
include_directories(protobuf-c/google/protobuf)
include_directories(../shared/keccak)
include_directories(../shared)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(trezor_c_sources
    kokko.c
    terminal.c
    ../shared/sha512.c
    ../shared/crypto-xmr.c
    ../shared/stream.c
    ../shared/key_exchange.c
    ../shared/fe.c
    ../shared/keccak/KeccakSponge.c
    ../shared/keccak/KeccakNISTInterface.c
    ../shared/keccak/KeccakF-1600-opt32.c
    protobuf-c/google/protobuf/descriptor.pb-c.c
    protobuf-c/protobuf-c/protobuf-c.c
    protobuf-c/types.pb-c.c
    protobuf-c/messages.pb-c.c
    protobuf-c/storage.pb-c.c
)

set(trezor_cpp_sources
    trezor.cpp
    trezorwallet.cpp
)

set(trezor_headers)
set(trezor_private_headers)

set(disabled_warnings_0 "-Wno-undef -Wno-aggregate-return -Wno-unused-variable -Wno-parentheses -Wno-unused-function -Wno-sign-compare -Wno-attributes")
if(NOT APPLE)
set(disabled_warnings_0 "${disabled_warnings_0} -Wno-unused-but-set-variable")
endif()
set(disabled_warnings_1 "${disabled_warnings_0} -Wno-old-style-definition -Wno-nested-externs -Wno-implicit-function-declaration")

set_source_files_properties(${trezor_c_sources} PROPERTIES COMPILE_FLAGS ${disabled_warnings_1})
set_source_files_properties(${trezor_cpp_sources} PROPERTIES COMPILE_FLAGS ${disabled_warnings_0})
    
bitmonero_private_headers(trezor
  	${trezor_private_headers})
bitmonero_add_library(trezor
  	${trezor_c_sources}
  	${trezor_cpp_sources}
  	${trezor_headers}
  	${trezor_private_headers})
target_link_libraries(trezor
  	LINK_PUBLIC
    hidapi
    trezorcrypto
)

add_subdirectory(test)
add_subdirectory(tools)
    
