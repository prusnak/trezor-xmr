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

############# trezor library tests
add_definitions(-DSIGS_INTERNAL_K -DRAW_USB_DUMP)
set(test_c_sources
  	random.c
  	crypto-xmr-test.c
  	kokko-test.c
    ../../shared/keccak/KeccakSponge.c
    ../../shared/keccak/KeccakNISTInterface.c
    ../../shared/keccak/KeccakF-1600-opt32.c
)

set(test_cpp_sources test.cpp)

set_source_files_properties(${test_c_sources} PROPERTIES COMPILE_FLAGS ${disabled_warnings_1})
set_source_files_properties(${test_cpp_sources} PROPERTIES COMPILE_FLAGS "-Wno-format -Wno-vla ${disabled_warnings_0}")
    
set(test_headers)
set(test_private_headers)
bitmonero_private_headers(trezortest
	${test_private_headers})
bitmonero_add_executable(trezortest
  	${test_c_sources}
  	${test_cpp_sources}
  	${test_headers}
  	${test_private_headers})
target_link_libraries(trezortest
	LINK_PUBLIC
    	trezor
    	crypto
  	LINK_PRIVATE
    	${Boost_FILESYSTEM_LIBRARY}
    	${Boost_SYSTEM_LIBRARY}
    	${Boost_THREAD_LIBRARY}
    	${CMAKE_THREAD_LIBS_INIT}
)

remove_definitions(-DRAW_USB_DUMP)
    