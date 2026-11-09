#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    /**
     * FAF addition. Lays the engine's colour-write mask and fill mode over the
     * blend and rasterizer states an effect pass just bound, where the pass
     * left them at their defaults (write everything, solid). A pass that
     * restricts its own mask or draws wireframe keeps its choice, as a D3D9
     * pass that sets COLORWRITEENABLE or FILLMODE overrides the backend's
     * render state. D3D10 hands back the existing object for a description it
     * has seen, so nothing needs caching here.
     */
    void ApplyStateOverrides(ID3D10Device* const device)
    {
      if (sColorWriteMask != D3D10_COLOR_WRITE_ENABLE_ALL) {
        ID3D10BlendState* bound = nullptr;
        FLOAT blendFactor[4]{};
        UINT sampleMask = 0U;
        device->OMGetBlendState(&bound, blendFactor, &sampleMask);

        D3D10_BLEND_DESC blendDesc = OpaqueBlendDesc(); // the pipeline default when nothing is bound
        if (bound != nullptr) {
          bound->GetDesc(&blendDesc);
        }
        if (blendDesc.RenderTargetWriteMask[0] == D3D10_COLOR_WRITE_ENABLE_ALL) {
          blendDesc.RenderTargetWriteMask[0] = sColorWriteMask;
          ID3D10BlendState* masked = nullptr;
          if (SUCCEEDED(device->CreateBlendState(&blendDesc, &masked))) {
            device->OMSetBlendState(masked, blendFactor, sampleMask);
            masked->Release();
          }
        }
        SafeRelease(bound);
      }

      if (sWireframe) {
        ID3D10RasterizerState* bound = nullptr;
        device->RSGetState(&bound);

        D3D10_RASTERIZER_DESC rasterizerDesc{}; // the pipeline default when nothing is bound
        rasterizerDesc.FillMode = D3D10_FILL_SOLID;
        rasterizerDesc.CullMode = D3D10_CULL_BACK;
        rasterizerDesc.DepthClipEnable = TRUE;
        if (bound != nullptr) {
          bound->GetDesc(&rasterizerDesc);
        }
        if (rasterizerDesc.FillMode == D3D10_FILL_SOLID) {
          rasterizerDesc.FillMode = D3D10_FILL_WIREFRAME;
          ID3D10RasterizerState* wireframe = nullptr;
          if (SUCCEEDED(device->CreateRasterizerState(&rasterizerDesc, &wireframe))) {
            device->RSSetState(wireframe);
            wireframe->Release();
          }
        }
        SafeRelease(bound);
      }
    }
}


  /**
   * Address: 0x00900FF0 (FUN_00900FF0)
   *
   * char const *,void *,void *
   *
   * What it does:
   * Initializes wrapper state for one D3D10 technique and retains the backing
   * effect interface through `AddRef`.
   */
  EffectTechniqueD3D10::EffectTechniqueD3D10(
    const char* const name, ID3D10Effect* const dxEffect, ID3D10EffectTechnique* const techniqueHandle
  )
    : name_()
    , dxEffect_(dxEffect)
    , techniqueHandle_(techniqueHandle)
    , beginEndActive_(false)
    , beginEndPadding_{}
  {
    name_.assign_owned((name != nullptr) ? name : "");

    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 39, "invalid effect specified");
    }

    dxEffect_->AddRef();
  }

  /**
   * Address: 0x00900F50 (FUN_00900F50)
   * Address: 0x00900FD0 (FUN_00900FD0, the scalar deleting destructor)
   *
   * What it does:
   * Releases the native effect. The name then goes as a member; the technique
   * handle and the begin/end flag are left as they are.
   */
  EffectTechniqueD3D10::~EffectTechniqueD3D10()
  {
    SafeRelease(dxEffect_);
  }

  /**
   * Address: 0x00900EF0 (FUN_00900EF0)
   *
   * What it does:
   * Returns the wrapper's local technique name.
   */
  fa::string* EffectTechniqueD3D10::GetName()
  {
    return &name_;
  }

  /**
   * Address: 0x00901110 (FUN_00901110)
   *
   * What it does:
   * Begins technique execution on the active device and returns pass count.
   */
  int EffectTechniqueD3D10::BeginTechnique()
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 56, "invalid effect technique");
    }

    Device::GetInstance()->BeginTechnique();

    D3D10_TECHNIQUE_DESC techniqueDesc{};
    const HRESULT result = techniqueHandle_->GetDesc(&techniqueDesc);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 67, result);
    }

    beginEndActive_ = true;
    return static_cast<int>(techniqueDesc.Passes);
  }

  /**
   * Address: 0x00901290 (FUN_00901290)
   *
   * What it does:
   * Ends the active technique lane and clears begin/end tracking.
   */
  void EffectTechniqueD3D10::EndTechnique()
  {
    if (!beginEndActive_) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 77, "effect technique begin/end mismatch");
    }

    Device::GetInstance()->EndTechnique();
    beginEndActive_ = false;
  }

  /**
   * Address: 0x00901360 (FUN_00901360)
   *
   * What it does:
   * Applies a pass from the active D3D10 technique handle.
   */
  void EffectTechniqueD3D10::BeginPass(const int pass)
  {
    if (!beginEndActive_) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 89, "effect technique begin/end mismatch");
    }

    const HRESULT result = techniqueHandle_->GetPassByIndex(static_cast<UINT>(pass))->Apply(0U);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 93, result);
    }

    // FAF addition (see ApplyStateOverrides); the shipped body ends at Apply.
    ApplyStateOverrides(static_cast<DeviceD3D10*>(Device::GetInstance())->mDevice);
  }

  /**
   * Address: 0x009014D0 (FUN_009014D0)
   *
   * What it does:
   * Validates pass sequencing for the currently active technique.
   */
  void EffectTechniqueD3D10::EndPass()
  {
    if (!beginEndActive_) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 98, "effect technique begin/end mismatch");
    }
  }

  /**
   * Address: 0x00901580 (FUN_00901580)
   *
   * What it does:
   * Fetches a boolean annotation by name from the current technique handle.
   */
  bool EffectTechniqueD3D10::GetAnnotationBool(bool* const outValue, const fa::string& annotationName)
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 105, "invalid effect technique");
    }

    ID3D10EffectVariable* const annotation = techniqueHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    BOOL boolValue = FALSE;
    const HRESULT result = annotation->AsScalar()->GetBool(&boolValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 115, result);
    }

    *outValue = (boolValue == 1);
    return true;
  }

  /**
   * Address: 0x00901710 (FUN_00901710)
   *
   * What it does:
   * Fetches an integer annotation by name from the current technique handle.
   */
  bool EffectTechniqueD3D10::GetAnnotationInt(int* const outValue, const fa::string& annotationName)
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 124, "invalid effect technique");
    }

    ID3D10EffectVariable* const annotation = techniqueHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    const HRESULT result = annotation->AsScalar()->GetInt(outValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 133, result);
    }

    return true;
  }

  /**
   * Address: 0x00901880 (FUN_00901880)
   *
   * What it does:
   * Fetches a float annotation by name from the current technique handle.
   */
  bool EffectTechniqueD3D10::GetAnnotationFloat(float* const outValue, const fa::string& annotationName)
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 140, "invalid effect technique");
    }

    ID3D10EffectVariable* const annotation = techniqueHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    const HRESULT result = annotation->AsScalar()->GetFloat(outValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 149, result);
    }

    return true;
  }

  /**
   * Address: 0x009019F0 (FUN_009019F0)
   *
   * What it does:
   * Fetches a string annotation by name from the current technique handle.
   */
  bool EffectTechniqueD3D10::GetAnnotationString(fa::string* const outValue, const fa::string& annotationName)
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 156, "invalid effect technique");
    }

    ID3D10EffectVariable* const annotation = techniqueHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    LPCSTR text = nullptr;
    const HRESULT result = annotation->AsString()->GetString(&text);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 166, result);
    }

    outValue->assign_owned((text != nullptr) ? text : "");
    return true;
  }
}

