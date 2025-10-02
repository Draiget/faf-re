#pragma once
#include <map>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
	class RObject;
    class RRef;
	class RType;
	class RField;
	class REnumType;
	class RIndexed;

	/**
	 * C-string comparator for map keys.
	 */
	struct CStrLess {
		bool operator()(const char* a, const char* b) const noexcept {
			if (a == b) return false;
			if (!a) return true;
			if (!b) return false;
			return std::strcmp(a, b) < 0;
		}
	};

	using TypeMap = std::map<const char*, RType*, CStrLess>;
	using TypeVec = msvc8::vector<RType*>;

	class RObject
	{
	public:
		/**
		 * Address: 0x00A82547
		 * VFTable SLOT: 0
		 */
		[[nodiscard]]
		virtual RType* GetClass() const = 0;

		/**
		 * Address: 0x00A82547
		 * VFTable SLOT: 1
		 */
		virtual RRef GetDerivedObjectRef() = 0;

		/**
		 * PDB name: sub_4012D0
		 * VFTable SLOT: 2
		 */
		virtual ~RObject() noexcept = default;
	};
	static_assert(sizeof(RObject) == 0x04, "RObject must be 0x04");

    // template<class T>
	class RRef
	{
	public:
		void* mObj;
		RType* mType;

        // RRef(T*);
        // RRef(void* ptr, gpg::RType* type) : mObj{ ptr }, mType{ type } {}

		msvc8::string GetLexical() const; // 0x004A35D0
		bool SetLexical(const char*) const; // 0x004A3600
		const char* GetTypeName() const; // gpgcore.dll
		RRef operator[](unsigned int ind) const; // 0x004A3610
		size_t GetCount() const; // 0x004A3630
		const RType* GetRType() const; // 0x004A3650
		const RIndexed* IsIndexed() const; // 0x004A3660
		const RIndexed* IsPointer() const; // 0x004CC9E0
		int GetNumBases() const; // gpgcore.dll
		RRef GetBase(int ind) const; // gpgcore.dll
		int GetNumFields() const; // 0x004CC9B0
		RRef GetField(int ind) const; // gpgcore.dll
		const char* GetFieldName(int ind) const; // gpgcore.dll
		void Delete(); // 0x008D8800
	};

    /**
	 * Global registries (original: func_GetRTypeMap / func_GetRTypeVec).
	 */
	inline TypeMap& GetRTypeMap() {
		static TypeMap gMap;
		return gMap;
	}

	inline TypeVec& GetRTypeVec() {
		static TypeVec gVec;
		return gVec;
	}

    class RField
    {
    public:
        const char* mName;
        RType* mType;
        int mOffset;
        int v4;
        const char* mDesc;

        RField(const char* name, RType* type, int offset);
        RField(const char* name, RType* type, int offset, int v, const char* desc);
    };

    class RType : public RObject
    {
        // Primary vftable (11 entries)
    public:
        using save_construct_args_func_t = void (*)(void*);
        using save_func_t = void (*)(WriteArchive*, int, int, RRef*);
        using construct_func_t = void (*)(void*);
        using load_func_t = void (*)(ReadArchive*, int, int, RRef*);
        using new_ref_func_t = RRef(*)();
        using cpy_ref_func_t = RRef(*)(RRef*);
        using delete_func_t = void (*)(void*);
        using ctor_ref_func_t = RRef(*)(void*);
        using mov_ref_func_t = RRef(*)(void*, RRef*);
        using dtr_func_t = void (*)(void*);

        /**
         * In binary: returns the family descriptor (descriptor for gpg::RType).
         *
         * Address: 0x00401370
         * SLOT: 0
         */
        [[nodiscard]]
        virtual RType* GetClass() const = 0;

        /**
         * Packs { this, GetFamilyDescriptor() } into the provided handle.
         *
         * Address: 0x00401390
         * SLOT: 1
         */
        [[nodiscard]]
        virtual RRef GetDerivedObjectRef() = 0;

        /**
         * Destructor.
         *
         * Address: 0x008DD9D0
         * SLOT: 2
         */
        virtual ~RType();

        /**
         * Abstract: provide a label/name string for a given instance pointer.
         * In base RType default ToString uses this label with "%s at 0x%p".
         *
         * Address: 0x00A82547
         * SLOT: 3
         */
        virtual const char* GetName() = 0;

        /**
         * Default stringification: "<label> at 0x<ptr>".
         * Returns number of bytes appended.
         *
         * Address: 0x008DB100
         * SLOT: 4
         */
        virtual msvc8::string GetLexical(const RRef&);

        /**
         * Unknown (base: no-op/false).
         *
         * Address: 0x008D86E0
         * SLOT: 5
         */
        virtual bool SetLexical(const RRef&, const char*) const {
            return false;
        }

        /**
         * Unknown (observed as zero in base).
         *
         * Address: 0x004013B0
         * SLOT: 6
         */
        [[nodiscard]]
        virtual RIndexed* IsIndexed() {
            return nullptr;
        }

        /**
         * Unknown (observed as zero in base).
         *
         * Address: 0x004013C0
         * SLOT: 7
         */
        [[nodiscard]]
        virtual RIndexed* IsPointer() {
            return nullptr;
        }

        /**
         * Unknown (observed as zero in base).
         *
         * Address: 0x004013D0
         * SLOT: 8
         */
        [[nodiscard]]
        virtual REnumType* IsEnumType() {
            return nullptr;
        }

        /**
         * One-shot registration hook (called by lazy-init).
         *
         * Address: 0x008D8680
         * SLOT: 9
         */
        virtual void Init() = 0;

        /**
         * Finalization: builds indices over 20-byte member records.
         *
         * Address: 0x008DF4A0
         * SLOT: 10
         */
        virtual void Finish() = 0;

        /**
         * Address: 0x008D8640
         */
        void Version(int version);

        /**
         * Add a base-class reference and flatten its fields into this type.
         * - Fails if initialization is already finished (matches original assert).
         * - Appends `base` into `bases_`.
         * - For each field of `base.mType`, appends a copy into `fields_` with
         *   offset adjusted by `base.mOffset`.
         *
         * Address: 0x008DF500
         */
        void AddBase(const RField& field);

        /**
         * Register this type in global registries.
         *
         * Address: 0x008DF960
         */
        void RegisterType();

        /**
         * Binary-search a field by its name.
         * Preconditions:
         *  - `initFinished_` must be true (indices built, `fields_` sorted by name).
         *  - `fields_` is sorted ascending by `RField::mName` (strcmp order).
         * Returns:
         *  - Pointer to matching RField if found;
         *  - nullptr if not found or container is empty.
         *
         * Address: 0x008D94E0
         */
        const RField* GetFieldNamed(const char* name) const;

        /**
         * Check if `this` is (transitively) derived from `baseType`.
         * If `outOffset` is provided and relation holds, accumulates byte offset
         * from `this` object start to the subobject of type `baseType`.
         * Throws std::runtime_error("Ambiguous base class") if there are >=2 distinct base paths.
         *
         * Address: 0x008DBFF0
         */
        bool IsDerivedFrom(const RType* baseType, int32_t* outOffset) const;

    public:
        bool finished_;
        bool initFinished_;
        int size_;
        int version_;
        save_construct_args_func_t serSaveConstructArgsFunc_;
        save_func_t serSaveFunc_;
        construct_func_t serConstructFunc_;
        load_func_t serLoadFunc_;
        int v8;
        int v9;
        msvc8::vector<RField> bases_;
        msvc8::vector<RField> fields_;
        new_ref_func_t newRefFunc_;
        cpy_ref_func_t cpyRefFunc_;
        delete_func_t deleteFunc_;
        ctor_ref_func_t ctorRefFunc_;
        mov_ref_func_t movRefFunc_;
        dtr_func_t dtrFunc_;
        bool v24;

    public:
        template<class T>
        RField* AddField(const char* name, int offset) {
            GPG_ASSERT(!initFinished_); // if (this->mInitFinished) { gpg::HandleAssertFailure("!mInitFinished", 734, "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/reflection.h"); }
            RField f{ T::StaticGetClass(), name, offset };
            this->fields_.push_back(f);
            return &this->fields_.back();
        }

        template<class T, class B>
        void AddBase() {
            RType* type = B::StaticGetClass();
            this->AddBase(RField{
                type->GetName(),
                type,
                offsetof(T, B) // !
            });
        }
    };
    static_assert(sizeof(RType) == 100, "RType must be 100 bytes on x86");

    /**
     * VFTABLE: 0x00D48CA0
     * COL:  0x00E5DC40
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
     */
    class REnumType : public RType {
    public:
        struct ROptionValue
        {
            int mValue;
            const char* mName;
        };

        /**
         * In binary:
         *
         * Address: 0x00418120
         * VFTable SLOT: 2
         */
        ~REnumType() override = default;

        /**
         * In binary:
         *
         * Address: 0x008E1C40
         * VFTable SLOT: 4
         */
        [[nodiscard]]
        msvc8::string GetLexical(const RRef& ref) override;

        /**
         * In binary:
         *
         * Address: 0x008D9670
         * VFTable SLOT: 5
         */
        bool SetLexical(const RRef&, const char*) const override;

        /**
         * In binary:
         *
         * Address: 0x004180F0
         * VFTable SLOT: 8
         */
        REnumType* IsEnumType() override {
            return this;
        }

        const msvc8::vector<ROptionValue>& GetEnumOptions() {
            return mEnumNames;
        }

        /**
         * In binary:
         *
         * Address: 0x008D86F0
         */
        const char* StripPrefix(const char*) const;

        bool GetEnumValue(const char*, int*) const;

        /**
         * In binary:
         *
         * Address: 0x008DF5F0
         */
        void AddEnum(char const* name, int index);

    public:
        const char* mPrefix;
        msvc8::vector<ROptionValue> mEnumNames;
    };
    static_assert(sizeof(REnumType) == 120, "REnumType must be 120 bytes on x86");

    class RIndexed
    {
    public:
        virtual RRef SubscriptIndex(void* obj, int ind) const = 0;

        virtual size_t GetCount(void* obj) const = 0;

        virtual void SetCount(void* obj, int count) const {
            throw std::bad_cast{};
        } // 0x004012F0

        virtual void AssignPointer(void* obj, const RRef& from) const {
            throw std::bad_cast{};
        } // 0x00401320
    };
}
