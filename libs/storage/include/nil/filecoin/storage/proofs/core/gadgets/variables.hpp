#ifndef FILECOIN_STORAGE_PROOFS_CORE_GADGETS_VARIABLES_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_GADGETS_VARIABLES_HPP

#include <boost/variant.hpp>

namespace filecoin {
    /// Root represents a root commitment which may be either a raw value or an already-allocated number.
    /// This allows subcomponents to depend on roots which may optionally be shared with their parent
    /// or sibling components.
    template<typename Engine, template<typename> class AllocatedNumber>
    using root = boost::variant<AllocatedNumber<Engine>, typename Engine::Fr>;

}    // namespace filecoin

#endif