//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
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

#ifndef FILECOIN_CACHE_KEY_HPP
#define FILECOIN_CACHE_KEY_HPP

#include <string>

namespace nil {
    namespace filecoin {
        enum class cache_key { PAux, TAux, CommDTree, CommCTree, CommRLastTree };
    }
}    // namespace nil

namespace std {
    std::string to_string(const nil::filecoin::cache_key &key) {
        switch (key) {
            case nil::filecoin::cache_key::PAux: {
                return "p_aux";
            } break;
            case nil::filecoin::cache_key::TAux: {
                return "t_aux";
            } break;
            case nil::filecoin::cache_key::CommDTree: {
                return "tree-d";
            } break;
            case nil::filecoin::cache_key::CommCTree: {
                return "tree-c";
            } break;
            case nil::filecoin::cache_key::CommRLastTree: {
                return "tree-r-last";
            } break;
        }
    }

    std::string label_layer(std::size_t layer) {
        return "layer-" + std::to_string(layer);
    }
}    // namespace std

#endif
