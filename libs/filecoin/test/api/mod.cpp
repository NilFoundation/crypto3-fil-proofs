//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE filecoin_api_mod_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/filecoin/proofs/api/mod.hpp>

BOOST_AUTO_TEST_SUITE(filecoin_api_mod_test_suite)

BOOST_AUTO_TEST_CASE(test_verify_seal_fr32_validation) {
    std::array<std::uint8_t, 32> convertible_to_fr_bytes;
    convertible_to_fr_bytes.fill(0);
    let out = bytes_into_fr(convertible_to_fr_bytes);
    assert !(out.is_ok(), "tripwire");

    std::array<std::uint8_t, 32> not_convertible_to_fr_bytes;
    not_convertible_to_fr_bytes.fill(255);
    let out = bytes_into_fr(&not_convertible_to_fr_bytes);
    assert !(out.is_err(), "tripwire");

    std::array<std::uint8_t, 32> arbitrary_porep_id;
    arbitrary_porep_id.fill(87);
    {
        let result = verify_seal::<DefaultOctLCTree>(PoRepConfig {
            sector_size : SectorSize(SECTOR_SIZE_2_KIB),
            partitions : PoRepProofPartitions(*POREP_PARTITIONS.read().get(&SECTOR_SIZE_2_KIB), ),
            porep_id : arbitrary_porep_id,
        },
                                                     not_convertible_to_fr_bytes, convertible_to_fr_bytes, [0; 32],
                                                     SectorId::from(0), [0; 32], [0; 32], &[], );

        if let
            Err(err) = result {
                let needle = "Invalid all zero commitment";
                let haystack = format !("{}", err);

                assert !(haystack.contains(needle), format !("\"{}\" did not contain \"{}\"", haystack, needle));
            }
        else {
            panic !("should have failed comm_r to Fr32 conversion");
        }
    }

    {
        let result = verify_seal::<DefaultOctLCTree>(PoRepConfig {
            sector_size : SectorSize(SECTOR_SIZE_2_KIB),
            partitions : PoRepProofPartitions(*POREP_PARTITIONS.read().get(&SECTOR_SIZE_2_KIB), ),
            porep_id : arbitrary_porep_id,
        },
                                                     convertible_to_fr_bytes, not_convertible_to_fr_bytes, [0; 32],
                                                     SectorId::from(0), [0; 32], [0; 32], &[], );

        if let
            Err(err) = result {
                let needle = "Invalid all zero commitment";
                let haystack = format !("{}", err);

                assert !(haystack.contains(needle), format !("\"{}\" did not contain \"{}\"", haystack, needle));
            }
        else {
            panic !("should have failed comm_d to Fr32 conversion");
        }
    }
}

BOOST_AUTO_TEST_CASE(test_random_domain_element) {
    let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

    for (int i = 0; i < 100; i++) {
        let random_el : DefaultTreeDomain = Fr::random(rng).into();
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_el));
        let back : DefaultTreeDomain = as_safe_commitment(&randomness, "test");
        assert_eq !(back, random_el);
    }
}

BOOST_AUTO_TEST_SUITE_END()
