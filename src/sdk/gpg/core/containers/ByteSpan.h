#pragma once

namespace gpg
{
    /**
     * Very small SSO-less byte span holder used only to mirror the decompiled call pattern.
     */
    struct ByteSpan {
        const char* begin{};
        const char* end{};

        [[nodiscard]]
    	size_t size() const {
	        return static_cast<size_t>(end - begin);
        }
    };
}
