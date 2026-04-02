#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
  class EffectD3D9;
  class EffectTechniqueD3D9;
  class EffectVariableD3D9;
} // namespace gpg::gal

namespace moho
{
  class CD3DDevice;
  class ID3DTextureSheet;

  class CD3DEffect
  {
  public:
    template <typename T>
    struct SharedHandle
    {
      T* px;                                  // +0x00
      boost::detail::sp_counted_base* pi;     // +0x04
    };

    static_assert(sizeof(SharedHandle<void>) == 0x08, "CD3DEffect::SharedHandle size must be 0x08");

    struct AttachedLink
    {
      AttachedLink* mLinkLane; // +0x00
      AttachedLink* mNext;     // +0x04
    };

    template <typename NodeT>
    struct TreeMap
    {
      void* mAllocatorProxy; // +0x00
      NodeT* mHead;          // +0x04
      std::uint32_t mSize;   // +0x08
    };

    class Technique
    {
    public:
      class Implementation
      {
      public:
        struct IntAnnotationNode
        {
          IntAnnotationNode* mLeft;      // +0x00
          IntAnnotationNode* mParent;    // +0x04
          IntAnnotationNode* mRight;     // +0x08
          msvc8::string mKey;            // +0x0C
          std::int32_t mValue;           // +0x28
          std::uint8_t mColor;           // +0x2C
          std::uint8_t mIsNil;           // +0x2D
          std::uint8_t mPad2E[0x2];      // +0x2E
        };

        static_assert(offsetof(IntAnnotationNode, mKey) == 0x0C, "CD3DEffect::Technique::Implementation::IntAnnotationNode::mKey offset must be 0x0C");
        static_assert(offsetof(IntAnnotationNode, mValue) == 0x28, "CD3DEffect::Technique::Implementation::IntAnnotationNode::mValue offset must be 0x28");
        static_assert(offsetof(IntAnnotationNode, mColor) == 0x2C, "CD3DEffect::Technique::Implementation::IntAnnotationNode::mColor offset must be 0x2C");
        static_assert(offsetof(IntAnnotationNode, mIsNil) == 0x2D, "CD3DEffect::Technique::Implementation::IntAnnotationNode::mIsNil offset must be 0x2D");
        static_assert(sizeof(IntAnnotationNode) == 0x30, "CD3DEffect::Technique::Implementation::IntAnnotationNode size must be 0x30");

        struct StringAnnotationNode
        {
          StringAnnotationNode* mLeft;    // +0x00
          StringAnnotationNode* mParent;  // +0x04
          StringAnnotationNode* mRight;   // +0x08
          msvc8::string mKey;             // +0x0C
          msvc8::string mValue;           // +0x28
          std::uint8_t mColor;            // +0x44
          std::uint8_t mIsNil;            // +0x45
          std::uint8_t mPad46[0x2];       // +0x46
        };

        static_assert(offsetof(StringAnnotationNode, mKey) == 0x0C, "CD3DEffect::Technique::Implementation::StringAnnotationNode::mKey offset must be 0x0C");
        static_assert(offsetof(StringAnnotationNode, mValue) == 0x28, "CD3DEffect::Technique::Implementation::StringAnnotationNode::mValue offset must be 0x28");
        static_assert(offsetof(StringAnnotationNode, mColor) == 0x44, "CD3DEffect::Technique::Implementation::StringAnnotationNode::mColor offset must be 0x44");
        static_assert(offsetof(StringAnnotationNode, mIsNil) == 0x45, "CD3DEffect::Technique::Implementation::StringAnnotationNode::mIsNil offset must be 0x45");
        static_assert(sizeof(StringAnnotationNode) == 0x48, "CD3DEffect::Technique::Implementation::StringAnnotationNode size must be 0x48");

        template <typename NodeT>
        struct AnnotationTreeMap
        {
          void* mAllocatorProxy;  // +0x00
          NodeT* mHead;           // +0x04
          std::uint32_t mSize;    // +0x08
        };

        using IntAnnotationTree = AnnotationTreeMap<IntAnnotationNode>;
        using StringAnnotationTree = AnnotationTreeMap<StringAnnotationNode>;

        static_assert(sizeof(IntAnnotationTree) == 0x0C, "CD3DEffect::Technique::Implementation::IntAnnotationTree size must be 0x0C");
        static_assert(sizeof(StringAnnotationTree) == 0x0C, "CD3DEffect::Technique::Implementation::StringAnnotationTree size must be 0x0C");

        /**
         * Address: 0x0042BB80 (FUN_0042BB80)
         * Mangled: ??0Implementation@Technique@CD3DEffect@Moho@@QAE@@Z
         *
         * What it does:
         * Initializes one technique implementation lane with empty annotation trees.
         */
        Implementation();

        /**
         * Address: 0x0042BC10 (FUN_0042BC10)
         * Mangled: ??0Implementation@Technique@CD3DEffect@Moho@@QAE@@Z_0
         *
         * What it does:
         * Initializes one implementation lane and copies one lane-name string.
         */
        explicit Implementation(const msvc8::string& implementationName);

        /**
         * Address: 0x0042BCB0 (FUN_0042BCB0)
         * Address: 0x0042C130 (FUN_0042C130, deleting-dtor thunk)
         * Mangled: ??1Implementation@Technique@CD3DEffect@Moho@@QAE@@Z
         *
         * What it does:
         * Destroys both annotation trees and releases the implementation name.
         */
        ~Implementation();

        /**
         * Address: 0x0042C1D0 (FUN_0042C1D0)
         *
         * What it does:
         * Copies the lane name and both annotation maps from another implementation.
         */
        Implementation& operator=(const Implementation& other);

        /**
         * Address: 0x0042BDC0 (FUN_0042BDC0)
         *
         * What it does:
         * Looks up one integer annotation by key and writes the found value.
         */
        [[nodiscard]] bool TryGetIntegerAnnotation(const msvc8::string& annotationName, std::int32_t* outValue) const;

        /**
         * Address: 0x0042BE00 (FUN_0042BE00)
         *
         * What it does:
         * Looks up one string annotation by key and copies the stored value.
         */
        [[nodiscard]] bool TryGetStringAnnotation(const msvc8::string& annotationName, msvc8::string* outValue) const;

        virtual void UnknownVirtualSlot();

      public:
        msvc8::string mName;                     // +0x04
        IntAnnotationTree mIntegerAnnotations;   // +0x20
        StringAnnotationTree mStringAnnotations; // +0x2C
      };

      /**
       * Address: 0x0042BE40 (FUN_0042BE40)
       * Mangled: ??0Technique@CD3DEffect@Moho@@QAE@@Z
       *
       * What it does:
       * Initializes one technique with name text and three implementation lanes.
       */
      explicit Technique(const msvc8::string& techniqueName);

      /**
       * Address: 0x0042BEC0 (FUN_0042BEC0)
       * Address: 0x0042C1B0 (FUN_0042C1B0, deleting-dtor thunk)
       * Mangled: ??1Technique@CD3DEffect@Moho@@UAE@XZ
       *
       * What it does:
       * Destroys all implementation lanes and releases the technique name.
       */
      virtual ~Technique();

      /**
       * Address: 0x0042BF40 (FUN_0042BF40)
       *
       * What it does:
       * Finalizes one technique so all three fidelity implementation lanes are valid.
       */
      void FinalizeMissingImplementations();

      [[nodiscard]] Implementation* GetImplementationLanes() noexcept;
      [[nodiscard]] const Implementation* GetImplementationLanes() const noexcept;

    public:
      msvc8::string mName; // +0x04
      alignas(Implementation) std::uint8_t mImplementationStorage[sizeof(Implementation) * 3]; // +0x20
    };

    struct TechniqueNode
    {
      TechniqueNode* mLeft;    // +0x00
      TechniqueNode* mParent;  // +0x04
      TechniqueNode* mRight;   // +0x08
      Technique mTechnique;    // +0x0C
      std::uint8_t mColor;     // +0xD4
      std::uint8_t mIsNil;     // +0xD5
      std::uint8_t mPadD6[0x2];// +0xD6
    };

    using TechniqueTree = TreeMap<TechniqueNode>;

    static_assert(sizeof(TechniqueTree) == 0x0C, "CD3DEffect::TechniqueTree size must be 0x0C");
    static_assert(offsetof(TechniqueNode, mTechnique) == 0x0C, "CD3DEffect::TechniqueNode::mTechnique offset must be 0x0C");
    static_assert(offsetof(TechniqueNode, mColor) == 0xD4, "CD3DEffect::TechniqueNode::mColor offset must be 0xD4");
    static_assert(offsetof(TechniqueNode, mIsNil) == 0xD5, "CD3DEffect::TechniqueNode::mIsNil offset must be 0xD5");
    static_assert(sizeof(TechniqueNode) == 0xD8, "CD3DEffect::TechniqueNode size must be 0xD8");

    /**
     * Address: 0x0042C430 (FUN_0042C430)
     * Mangled: ??0CD3DEffect@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes one effect object with empty technique tree, metadata strings,
     * and cleared gal effect handles.
     */
    CD3DEffect();

    /**
     * Address: 0x0042C520 (FUN_0042C520)
     * Address: 0x00440BA0 (FUN_00440BA0, deleting thunk)
     * Mangled: ??1CD3DEffect@Moho@@QAE@XZ
     *
     * What it does:
     * Releases effect/technique shared handles, tears down technique definitions,
     * and unlinks all attached callback links.
     */
    ~CD3DEffect();

    /**
     * Address: 0x0042C3D0 (FUN_0042C3D0, Moho::CON_d3d_AntiAliasingSamples)
     *
     * What it does:
     * Console command handler that forwards one integer sample count to the
     * active D3D device anti-aliasing slot.
     */
    static void CON_d3d_AntiAliasingSamples(void* commandArgs);

    /**
     * Address: 0x0042C650 (FUN_0042C650, ?InitEffectFromFile@CD3DEffect@Moho@@QAE_NPBD@Z)
     *
     * What it does:
     * Loads one effect source file, merges compatibility preamble state, creates
     * the gal effect handle, and rebuilds technique fidelity definitions.
     */
    [[nodiscard]] bool InitEffectFromFile(const char* effectFilePath);

    /**
     * Address: 0x0042DB30 (FUN_0042DB30, ?EnumerateValidTechniques@CD3DEffect@Moho@@QAEXAAV?$vector@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@@Z)
     *
     * What it does:
     * Queries the current effect for all valid techniques and appends their names.
     */
    void EnumerateValidTechniques(msvc8::vector<msvc8::string>& outTechniqueNames);

    /**
     * Address: 0x00431C60 (FUN_00431C60)
     *
     * What it does:
     * Resolves one fidelity-definition node by technique name, returning the
     * tree sentinel when no exact match exists.
     */
    [[nodiscard]] TechniqueNode* GetFidelityDefinitions(const Technique& technique);

    /**
     * Address: 0x0042D290 (FUN_0042D290, ?SetTechnique@CD3DEffect@Moho@@QAEXPBD@Z)
     *
     * What it does:
     * Selects one technique on the backing gal effect, using the current
     * fidelity lane when the definition tree contains it.
     */
    void SetTechnique(const char* techniqueName);

    /**
     * Address: 0x0042D580 (FUN_0042D580)
     * Mangled: ?GetImplAnnotation@CD3DEffect@Moho@@AAE_NAAHABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@1@Z
     *
     * What it does:
     * Reads one integer annotation from one implementation technique lane.
     */
    [[nodiscard]] bool GetImplAnnotation(
      std::int32_t* outValue,
      const msvc8::string& implementationName,
      const msvc8::string& annotationName
    );

    /**
     * Address: 0x0042D640 (FUN_0042D640)
     * Mangled: ?GetIntegerAnnotation@CD3DEffect@Moho@@QAEHABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0H@Z
     *
     * What it does:
     * Returns one integer annotation for the selected technique/fidelity lane,
     * resolving from implementation annotation when cache is missing.
     */
    [[nodiscard]] std::int32_t GetIntegerAnnotation(
      const msvc8::string& techniqueName,
      const msvc8::string& annotationName,
      std::int32_t defaultValue
    );

    /**
     * Address: 0x0042D780 (FUN_0042D780)
     * Mangled: ?GetImplAnnotation@CD3DEffect@Moho@@AAE_NAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV34@1@Z
     *
     * What it does:
     * Reads one string annotation from one implementation technique lane.
     */
    [[nodiscard]] bool GetImplAnnotation(
      msvc8::string* outValue,
      const msvc8::string& implementationName,
      const msvc8::string& annotationName
    );

    /**
     * Address: 0x0042D840 (FUN_0042D840)
     * Mangled: ?GetStringAnnotation@CD3DEffect@Moho@@QAE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV34@00@Z
     *
     * What it does:
     * Returns one string annotation for the selected technique/fidelity lane,
     * resolving from implementation annotation when cache is missing.
     */
    [[nodiscard]] msvc8::string GetStringAnnotation(
      const msvc8::string& techniqueName,
      const msvc8::string& annotationName,
      const msvc8::string& defaultValue
    );

    /**
     * Address: 0x00437E90 (FUN_00437E90, ?GetBaseEffect@CD3DEffect@Moho@@QAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
     *
     * What it does:
     * Returns a shared handle copy of the current base GAL effect lane.
     */
    [[nodiscard]] boost::shared_ptr<gpg::gal::EffectD3D9> GetBaseEffect();

    /**
     * Address: 0x0042DA30 (FUN_0042DA30, ?SetTexture@CD3DEffect@Moho@@QAEXPBDV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@@Z)
     *
     * What it does:
     * Resolves one effect variable by name and binds one texture handle (or
     * clears the slot when texture is null).
     */
    void SetTexture(const char* variableName, boost::shared_ptr<ID3DTextureSheet> texture);

  public:
    AttachedLink* mAttachedLinks; // +0x00
    TechniqueTree mTechniques;    // +0x04
    msvc8::string mName;          // +0x10
    msvc8::string mFile;          // +0x2C
    SharedHandle<gpg::gal::EffectD3D9> mEffect;                     // +0x48
    SharedHandle<gpg::gal::EffectTechniqueD3D9> mCurrentTechnique;  // +0x50
  };

  static_assert(offsetof(CD3DEffect::Technique::Implementation, mName) == 0x04, "CD3DEffect::Technique::Implementation::mName offset must be 0x04");
  static_assert(offsetof(CD3DEffect::Technique::Implementation, mIntegerAnnotations) == 0x20, "CD3DEffect::Technique::Implementation::mIntegerAnnotations offset must be 0x20");
  static_assert(offsetof(CD3DEffect::Technique::Implementation, mStringAnnotations) == 0x2C, "CD3DEffect::Technique::Implementation::mStringAnnotations offset must be 0x2C");
  static_assert(sizeof(CD3DEffect::Technique::Implementation) == 0x38, "CD3DEffect::Technique::Implementation size must be 0x38");

  static_assert(offsetof(CD3DEffect::Technique, mName) == 0x04, "CD3DEffect::Technique::mName offset must be 0x04");
  static_assert(offsetof(CD3DEffect::Technique, mImplementationStorage) == 0x20, "CD3DEffect::Technique::mImplementationStorage offset must be 0x20");
  static_assert(sizeof(CD3DEffect::Technique) == 0xC8, "CD3DEffect::Technique size must be 0xC8");

  static_assert(offsetof(CD3DEffect, mAttachedLinks) == 0x00, "CD3DEffect::mAttachedLinks offset must be 0x00");
  static_assert(offsetof(CD3DEffect, mTechniques) == 0x04, "CD3DEffect::mTechniques offset must be 0x04");
  static_assert(offsetof(CD3DEffect, mName) == 0x10, "CD3DEffect::mName offset must be 0x10");
  static_assert(offsetof(CD3DEffect, mFile) == 0x2C, "CD3DEffect::mFile offset must be 0x2C");
  static_assert(offsetof(CD3DEffect, mEffect) == 0x48, "CD3DEffect::mEffect offset must be 0x48");
  static_assert(
    offsetof(CD3DEffect, mCurrentTechnique) == 0x50,
    "CD3DEffect::mCurrentTechnique offset must be 0x50"
  );
  static_assert(sizeof(CD3DEffect) == 0x58, "CD3DEffect size must be 0x58");
} // namespace moho
