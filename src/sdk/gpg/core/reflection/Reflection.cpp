#include "Reflection.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <stdexcept>

#include "gpg/core/containers/String.h"
using namespace gpg;

RField::RField()
    : mName(nullptr),
      mType(nullptr),
      mOffset(0),
      v4(0),
      mDesc(nullptr) {
}

RField::RField(const char* name, RType* type, const int offset)
    : mName(name),
      mType(type),
      mOffset(offset),
      v4(0),
      mDesc(nullptr) {
}

RField::RField(const char* name, RType* type, const int offset, const int v, const char* desc)
    : mName(name),
      mType(type),
      mOffset(offset),
      v4(v),
      mDesc(desc) {
}

RType* gpg::LookupRType(const std::type_info& typeInfo) {
    TypeInfoMap& preregistered = GetRTypePreregisteredMap();
    const TypeInfoMap::iterator it = preregistered.find(&typeInfo);
    if (it == preregistered.end()) {
        const msvc8::string msg = STR_Printf(
            "Attempting to lookup the RType for %s before it is registered.",
            typeInfo.name());
        throw std::runtime_error(msg.c_str());
    }

    RType* type = it->second;
    if (!type->finished_) {
        type->finished_ = true;
        type->Init();
        type->RegisterType();
        type->initFinished_ = true;
    }

    return type;
}

void gpg::PreRegisterRType(const std::type_info& typeInfo, RType* type) {
    GetRTypePreregisteredMap().insert(TypeInfoMap::value_type(&typeInfo, type));
}

void gpg::REF_RegisterAllTypes() {
    std::stringstream errs;

    for (TypeInfoMap::const_iterator it = GetRTypePreregisteredMap().begin();
         it != GetRTypePreregisteredMap().end();
         ++it) {
        try {
            (void)LookupRType(*it->first);
        } catch (const std::exception& ex) {
            errs << ex.what() << std::endl;
        }
    }

    const std::string aggregated = errs.str();
    if (!aggregated.empty()) {
        throw std::runtime_error(aggregated);
    }
}

const RType* gpg::REF_GetTypeIndexed(const int index) {
    return GetRTypeVec()[index];
}

msvc8::string RRef::GetLexical() const {
	return mType->GetLexical(*this);
}

bool RRef::SetLexical(const char* name) const {
    return mType->SetLexical(*this, name);
}

const char* RRef::GetTypeName() const {
    if (!mType) {
        return "null";
    }

    return mType->GetName();
}

RRef RRef::operator[](const unsigned int ind) const {
    const RIndexed* indexed = mType->IsIndexed();
    return indexed->SubscriptIndex(mObj, static_cast<int>(ind));
}

size_t RRef::GetCount() const {
    const RIndexed* indexed = mType->IsIndexed();
    if (!indexed) {
        return 0;
    }

    return indexed->GetCount(mObj);
}

const RType* RRef::GetRType() const {
    return mType;
}

const RIndexed* RRef::IsIndexed() const {
    return mType->IsIndexed();
}

const RIndexed* RRef::IsPointer() const {
    return mType->IsPointer();
}

int RRef::GetNumBases() const {
    const RField* first = mType->bases_.begin();
    if (!first) {
        return 0;
    }

    return static_cast<int>(mType->bases_.end() - first);
}

RRef RRef::GetBase(const int ind) const {
    const RField* first = mType->bases_.begin();
    const RField& base = first[ind];

    RRef out{};
    out.mObj = static_cast<char*>(mObj) + base.mOffset;
    out.mType = base.mType;
    return out;
}

int RRef::GetNumFields() const {
    const RField* first = mType->fields_.begin();
    if (!first) {
        return 0;
    }

    return static_cast<int>(mType->fields_.end() - first);
}

RRef RRef::GetField(const int ind) const {
    const RField* first = mType->fields_.begin();
    const RField& field = first[ind];

    RRef out{};
    out.mObj = static_cast<char*>(mObj) + field.mOffset;
    out.mType = field.mType;
    return out;
}

const char* RRef::GetFieldName(const int ind) const {
    return mType->fields_.begin()[ind].mName;
}

void RRef::Delete() {
    if (!mObj) {
        return;
    }

    GPG_ASSERT(mType->deleteFunc_);
    mType->deleteFunc_(mObj);
}

RType::~RType() = default;

RType* RType::GetClass() const {
    static RType* familyDescriptor = nullptr;
    if (!familyDescriptor) {
        familyDescriptor = LookupRType(typeid(RType));
    }
    return familyDescriptor;
}

RRef RType::GetDerivedObjectRef() {
    RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
}

msvc8::string RType::GetLexical(const RRef& ref) const {
    const auto name = GetName();
    return STR_Printf("%s at 0x%p", name, ref.mObj);
}

void RType::Init() {
}

void RType::Finish() {
    GPG_ASSERT(!initFinished_);

    RField* first = fields_.begin();
    if (!first) {
        return;
    }

    RField* last = fields_.end();
    if (first == last) {
        return;
    }

    std::sort(first, last, [](const RField& a, const RField& b) {
        return std::strcmp(a.mName, b.mName) < 0;
    });
}

void RType::Version(const int version) {
    GPG_ASSERT(version_ == 0 || version_ == version);
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
    GPG_ASSERT(initFinished_);

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
    if (this == baseType) {
        if (outOffset) {
            *outOffset = 0;
        }

        return true;
    }

    const RField* first = bases_.begin();
    if (!first) {
        return false;
    }

    const RField* last = bases_.end();
    if (first == last) {
        return false;
    }

    bool found = false;

    for (const RField* it = first; it != last; ++it) {
        if (it->mType->IsDerivedFrom(baseType, outOffset)) {
            if (found) {
                throw std::runtime_error("Ambiguous base class");
            }

            if (outOffset) {
                *outOffset += it->mOffset;
            }

            found = true;
        }
    }

    return found;
}


msvc8::string REnumType::GetLexical(const RRef& ref) const {
    const int* enumValue = static_cast<const int*>(ref.mObj);
    const int value = enumValue ? *enumValue : 0;

    const ROptionValue* it = mEnumNames.begin();
    const ROptionValue* end = mEnumNames.end();
    for (; it != end; ++it) {
        if (it->mValue == value) {
            return msvc8::string(it->mName ? it->mName : "");
        }
    }

    return STR_Printf("%d", value);
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
            if (!ParseNum(tokenBegin, tokenEnd, &num)) {
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

