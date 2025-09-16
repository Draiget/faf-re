#pragma once

namespace gpg::core
{
    template <class T>
    struct IntrusiveLink {
        // Layout here is intentionally opaque; game uses doubly-linked ring.
        T prev{ nullptr };
        T next{ nullptr };
    };
}
