#include "Reflection.h"

#include "gpg/core/containers/String.h"
using namespace gpg;

msvc8::string RRef::GetLexical() const {
	return mType->GetLexical(*this);
}

bool RRef::SetLexical(const char* name) const {
    return mType->SetLexical(*this, name);
}

RType::~RType() = default;

msvc8::string RType::GetLexical(const RRef& ref) {
    const auto name = GetName();
    return STR_Printf("%s at 0x%p", name, reinterpret_cast<uintptr_t>(ref.mObj));
}

void RType::Version(const int version) {
    GPG_ASSERT(version_ == version);
    version_ = version;
}

void RType::AddBase(const RField& field) {
    GPG_ASSERT(!initFinished_);

    // Register the base link itself.
    bases_.push_back(field);

    // Flatten base fields into this->fields_ with offset adjustment.
    const RType* baseType = field.mType;
    if (!baseType) {
        return;
    }

    // MSVC8 vector layout may expose raw pointers;
    // keep null-safe checks like in the original.
    const RField* it = baseType->fields_.begin();
    const RField* end = baseType->fields_.end();
    if (!it) return; // consistent with original early-exit when start==nullptr

    for (; it < end; ++it) {
        // Copy-by-value semantics;
        // strings/descriptions are pointer aliases in the original.
        RField out{
            // same literal pointer as in base
            it->mName,
            // same field type
            it->mType,
            // adjust offset by base field offset
            field.mOffset + it->mOffset
        };

        out.v4 = it->v4;
        out.mDesc = it->mDesc;

        fields_.push_back(out);
    }
}

void RType::RegisterType() {
    // 1) Map name -> type
    // original: this->vtable->GetName(this)
    const char* name = GetName();
    // original: *sub_8DF330(map, &name) = this;
    GetRTypeMap()[name] = this;

    // 2) Append to global type list
    GetRTypeVec().push_back(this);
}

const RField* RType::GetFieldNamed(const char* name) const {
    GPG_ASSERT(!initFinished_);

    const RField* start = fields_.begin();
    if (!start) {
        return nullptr;
    }

    const RField* finish = fields_.end();
    if (start == finish) {
        return nullptr;
    }

    // Classic binary search over [lo, hi)
    std::size_t lo = 0;
    std::size_t hi = static_cast<std::size_t>(finish - start);

    while (lo < hi) {
        const std::size_t mid = (lo + hi) >> 1;
        const RField* elem = &start[mid];

        const int cmp = std::strcmp(name, elem->mName);
        if (cmp < 0) {
            hi = mid;
        } else if (cmp > 0) {
            lo = mid + 1;
        } else {
            // exact match
            return elem;
        }
    }
    return nullptr;
}

bool RType::IsDerivedFrom(const RType* baseType, int32_t* outOffset) const {
    // Base case: same type
    if (this == baseType) {
        if (outOffset) *outOffset = 0;
        return true;
    }

    // Null/empty base list - not derived
    const RField* first = bases_.begin();
    // MSVC8 empty-vector null start
    if (!first) {
        return false;
    }
    const RField* last = bases_.end();
    if (first == last) {
        return false;
    }

    bool found = false;

    // Iterate all direct bases
    for (const RField* it = first; it != last; ++it) {
        const RType* bType = it->mType;
        const int32_t bOffset = it->mOffset;

        // Recurse into base type; pass same outOffset pointer (as in original)
        if (!bType) continue;

        // Save current offset to allow safe accumulation after a successful path
        int32_t subOffset = 0;
        int32_t* pAccum = outOffset ? &subOffset : nullptr;

        if (bType->IsDerivedFrom(baseType, pAccum)) {
            // Already have a successful path? -> ambiguous
            if (found) {
                throw std::runtime_error("Ambiguous base class");
            }

            // First successful path: accumulate base edge offset
            if (outOffset) {
                // subOffset contains nested path offset; add current edge
                *outOffset = subOffset + bOffset;
            }
            found = true;
        }
    }

    return found;
}


msvc8::string REnumType::GetLexical(const RRef& ref) {
    // Guard: if no storage, treat as zero
    const auto pVal = static_cast<const int*>(ref.mObj);
    const int val = pVal ? *pVal : 0;

    // Try to find exact value match
    for (const auto& [mValue, mName] : mEnumNames) {
        if (mValue == val) {
            return msvc8::string(mName ? mName : "");
        }
    }

    return RType::GetLexical(ref);
}


bool REnumType::SetLexical(const RRef& dest, const char* str) const {
    if (!str || !dest.mObj) {
        return false;
    }

    int acc = 0;

    while (true) {
        // Find next separator and define token range
        const char* sep = std::strchr(str, '|');
        const char* tokenEnd = sep ? sep : (str + std::strlen(str));

        // Optional, case-sensitive prefix stripping
        const char* tokenBegin = str;
        if (mPrefix) {
            const std::size_t pn = std::strlen(mPrefix);
            if (std::strncmp(str, mPrefix, pn) == 0) {
                tokenBegin = str + pn;
            }
        }

        const std::size_t n = static_cast<std::size_t>(tokenEnd - tokenBegin);

        int  num = 0;
        bool matched = false;

        // Try case-insensitive exact name match
        for (const ROptionValue& opt : mEnumNames) {
            const char* name = opt.mName ? opt.mName : "";

            bool eq = false;
#if defined(_WIN32)
            // _memicmp returns 0 if equal (case-insensitive)
            if (_memicmp(tokenBegin, name, n) == 0 && name[n] == '\0') {
                eq = true;
            }
#else
            // Manual case-insensitive compare for first n chars
            std::size_t i = 0;
            for (; i < n; ++i) {
                unsigned char a = static_cast<unsigned char>(tokenBegin[i]);
                unsigned char b = static_cast<unsigned char>(name[i]);
                if (std::tolower(a) != std::tolower(b))
                    break;
            }
            if (i == n && name[n] == '\0')
                eq = true;
#endif

            if (eq) {
                num = opt.mValue;
                matched = true;
                break;
            }
        }

        // Fallback: numeric parse from span [tokenBegin, tokenEnd)
        if (!matched) {
            if (!func_ParseNum(tokenBegin, tokenEnd, &num)) {
                return false;
            }
        }

        // Accumulate OR
        acc |= num;

        // Commit on last token
        if (!sep) {
            *static_cast<int*>(dest.mObj) = acc;
            return true;
        }

        // Next token
        str = sep + 1;
    }
}

const char* REnumType::StripPrefix(const char* name) const {
    // Fast path: no prefix configured
    if (!mPrefix || !*mPrefix) {
        return name;
    }

    // Compute prefix length once (the original code effectively did strlen twice)
    const std::size_t n = std::strlen(mPrefix);
    if (std::strncmp(name, mPrefix, n) == 0) {
        return name + n;
    }

    return name;
}

bool REnumType::GetEnumValue(const char* name, int* outVal) const {
    const ROptionValue* it = mEnumNames.begin();
    const ROptionValue* end = mEnumNames.end();
    for (; it != end; ++it) {
#if defined(_WIN32)
        if (_stricmp(it->mName, name) == 0) {
            *outVal = it->mValue; return true;
        }
#else
        if (strcasecmp(it->mName, name) == 0) {
            *outVal = it->mValue; return true;
        }
#endif
    }
    return false;
}

void REnumType::AddEnum(char const* name, const int index) {
    const ROptionValue opt{ index, name };
    mEnumNames.push_back(opt);
}

