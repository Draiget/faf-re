#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{

  /**
   * Address: 0x0094C070 (FUN_0094C070)
   *
   * EffectContext const &,void *
   *
   * What it does:
   * Starts from an empty context and a null effect, then adopts the caller's
   * through `SetEffect`.
   */
  EffectD3D10::EffectD3D10(const EffectContext& context, ID3D10Effect* const dxEffect)
  {
    SetEffect(context, dxEffect);
  }

  /**
   * Address: 0x0094BF10 (FUN_0094BF10)
   *
   * What it does:
   * Releases the native effect and assigns a fresh context over `context_`.
   */
  void EffectD3D10::Reset()
  {
    SafeRelease(dxEffect_);
    context_ = EffectContext();
  }

  /**
   * Address: 0x0094BFE0 (FUN_0094BFE0)
   *
   * What it does:
   * Resets, copies `context` into `context_`, adopts `dxEffect`, then empties
   * the copied source buffer (the four words at this+0x48..+0x54, releasing
   * the shared owner at +0x4C first).
   */
  void EffectD3D10::SetEffect(const EffectContext& context, ID3D10Effect* const dxEffect)
  {
    Reset();
    context_ = context;
    dxEffect_ = dxEffect;
    context_.mSourceBuffer.Reset();
  }

  /**
   * Address: 0x0094BF80 (FUN_0094BF80)
   * Address: 0x0094C050 (FUN_0094C050, the scalar deleting destructor)
   *
   * What it does:
   * `Reset()`; `context_` is then destroyed once, as a member (0x0093F950).
   */
  EffectD3D10::~EffectD3D10()
  {
    Reset();
  }

  /**
   * Address: 0x0094B5D0 (FUN_0094B5D0)
   *
   * What it does:
   * Returns the embedded effect-context lane at `this+0x04`.
   */
  EffectContext* EffectD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x0094BC60 (FUN_0094BC60)
   *
   * fa::vector<boost::shared_ptr<gpg::gal::EffectTechnique>> &
   *
   * What it does:
   * Walks the techniques by index and appends a wrapper for every valid one:
   * the same `push_back` emission as the D3D9 backend (0x00942860, called at
   * 0x0094BE69), on a temporary whose constructor the binary inlines around
   * `shared_count(EffectTechniqueD3D10*)` 0x0094B6C0.
   */
  void EffectD3D10::GetTechniques(fa::vector<boost::shared_ptr<EffectTechnique>>& outTechniques)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 52, "invalid effect");
    }

    D3D10_EFFECT_DESC effectDesc{};
    HRESULT result = dxEffect_->GetDesc(&effectDesc);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectD3D10.cpp", 57, result);
    }

    for (UINT index = 0U; index < effectDesc.Techniques; ++index) {
      ID3D10EffectTechnique* const techniqueHandle = dxEffect_->GetTechniqueByIndex(index);
      if ((techniqueHandle == nullptr) || !techniqueHandle->IsValid()) {
        continue;
      }

      D3D10_TECHNIQUE_DESC techniqueDesc{};
      result = techniqueHandle->GetDesc(&techniqueDesc);
      if (result < 0) {
        ThrowGalErrorFromHresult("EffectD3D10.cpp", 69, result);
      }

      outTechniques.push_back(
        boost::shared_ptr<EffectTechnique>(new EffectTechniqueD3D10(techniqueDesc.Name, dxEffect_, techniqueHandle))
      );
    }
  }

  /**
   * Address: 0x0094B8A0 (FUN_0094B8A0)
   *
   * char const *
   *
   * What it does:
   * Wraps the effect variable called `variableName`; throws when the effect
   * or the variable is missing.
   */
  boost::shared_ptr<EffectVariable> EffectD3D10::GetVariable(const char* const variableName)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 79, "invalid effect");
    }

    ID3D10EffectVariable* const variableHandle = dxEffect_->GetVariableByName(variableName);
    if (variableHandle == nullptr) {
      char message[512] = {};
      std::snprintf(
        message, sizeof(message), "invalid effect variable requested: %s", (variableName != nullptr) ? variableName : ""
      );
      ThrowGalError("EffectD3D10.cpp", 82, message);
    }

    return boost::shared_ptr<EffectVariable>(new EffectVariableD3D10(variableName, dxEffect_, variableHandle));
  }

  /**
   * Address: 0x0094BA80 (FUN_0094BA80)
   *
   * char const *
   *
   * What it does:
   * Wraps the technique called `techniqueName`; throws when the effect or
   * the technique is missing.
   */
  boost::shared_ptr<EffectTechnique> EffectD3D10::GetTechnique(const char* const techniqueName)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 89, "invalid effect");
    }

    ID3D10EffectTechnique* const techniqueHandle = dxEffect_->GetTechniqueByName(techniqueName);
    if (techniqueHandle == nullptr) {
      char message[512] = {};
      std::snprintf(
        message,
        sizeof(message),
        "invalid effect technique requested: %s",
        (techniqueName != nullptr) ? techniqueName : ""
      );
      ThrowGalError("EffectD3D10.cpp", 92, message);
    }

    return boost::shared_ptr<EffectTechnique>(new EffectTechniqueD3D10(techniqueName, dxEffect_, techniqueHandle));
  }

  /**
   * Address: 0x0094B5E0 (FUN_0094B5E0)
   *
   * What it does:
   * No-op D3D10 effect reset slot.
   */
  void EffectD3D10::OnReset() {}

  /**
   * Address: 0x0094B5F0 (FUN_0094B5F0)
   *
   * What it does:
   * No-op D3D10 effect lost-device slot.
   */
  void EffectD3D10::OnLost() {}
}

