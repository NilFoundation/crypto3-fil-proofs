#---------------------------------------------------------------------------//
#  MIT License
#
#  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
#  Copyright (c) 2020 Wukong Moscow Algorithm Lab
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#---------------------------------------------------------------------------//

include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       crypto3::algebra
                       crypto3::block
                       crypto3::codec
                       crypto3::hash
                       crypto3::multiprecision
                       crypto3::zk

                       actor::core
                       actor::network

                       ${Boost_LIBRARIES})

macro(define_storage_test test)
    get_filename_component(name ${test} NAME)
    set(target_name storage_${name}_test)

    while(TARGET ${target_name})
        get_filename_component(TEST_DIRECTORY ${test} DIRECTORY)
        get_filename_component(PARENT_DIR ${TEST_DIRECTORY} DIRECTORY)
        set(target_name ${PARENT_DIR}_${target_name})
    endwhile()

    cm_test(NAME ${target_name} SOURCES ${test}.cpp)

    target_include_directories(${target_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${target_name} PROPERTIES CXX_STANDARD 14)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${target_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    "core/crypto/feistel"

    "core/components/por"

    "core/merkle/proof"

    "core/pieces"
    "core/por"
    "core/fr32"

    "porep/drg/circuit"
    "porep/drg/compound"
    "porep/drg/vanilla"

    "porep/stacked/vanilla/challenges"
    "porep/stacked/vanilla/cache"
    "porep/stacked/vanilla/proof"

    "porep/stacked/circuit/create_label"
    "porep/stacked/circuit/proof"
    "porep/stacked/circuit/hash"

    "post/election/circuit"
    "post/election/compound"
    "post/election/vanilla"

    "post/fallback/circuit"
    "post/fallback/compound"
    "post/fallback/vanilla"

    "post/rational/circuit"
    "post/rational/compound"
    "post/rational/vanilla")

foreach(TEST_NAME ${TESTS_NAMES})
    define_storage_test(${TEST_NAME})
endforeach()
