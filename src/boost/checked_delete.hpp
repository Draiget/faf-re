// Found before boost's own header: src/ comes first on the include path.
//
// boost::scoped_ptr and shared_ptr delete through checked_delete, and the engine
// holds classes in them that have virtual functions and no virtual destructor. The
// binary's vtables fix that layout. This warning shows even in a system header, and
// clang decides by where the `delete` is written, so the pragma has to surround the
// include.
#pragma once

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdelete-non-abstract-non-virtual-dtor"
#include_next <boost/checked_delete.hpp>
#pragma clang diagnostic pop
