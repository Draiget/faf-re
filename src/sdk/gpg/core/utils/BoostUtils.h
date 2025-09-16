#pragma once

// Third-party mirror for documentation purpose only.
// This matches Boost 1.33-1.34 era behavior for MSVC8.

namespace boost
{
    namespace noncopyable_
	{
        class noncopyable
    	{
        protected:
            noncopyable() {}  // allow construction by derived
            ~noncopyable() {} // and destruction, but...
        private:
            // ...forbid copying and assignment
            noncopyable(noncopyable const&);  // not defined
            noncopyable& operator=(noncopyable const&); // not defined
        };

    }
} // namespace boost::noncopyable_

namespace boost {
    typedef noncopyable_::noncopyable noncopyable;
}
