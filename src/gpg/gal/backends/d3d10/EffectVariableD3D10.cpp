#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{

  /**
   * Address: 0x0094C1F0 (FUN_0094C1F0)
   *
   * char const *,void *,void *
   *
   * What it does:
   * Initializes variable wrapper lanes and retains the backing effect interface.
   */
  EffectVariableD3D10::EffectVariableD3D10(
    const char* const name, ID3D10Effect* const dxEffect, ID3D10EffectVariable* const variableHandle
  )
    : name_()
    , dxEffect_(dxEffect)
    , variableHandle_(variableHandle)
  {
    name_.assign_owned((name != nullptr) ? name : "");

    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 39, "invalid effect specified");
    }

    dxEffect_->AddRef();
  }

  /**
   * Address: 0x0094C150 (FUN_0094C150)
   * Address: 0x0094C1D0 (FUN_0094C1D0, the scalar deleting destructor)
   *
   * What it does:
   * Releases the native effect. The name then goes as a member; the variable
   * handle is left as it is.
   */
  EffectVariableD3D10::~EffectVariableD3D10()
  {
    SafeRelease(dxEffect_);
  }

  /**
   * Address: 0x0094C0E0 (FUN_0094C0E0)
   *
   * What it does:
   * Returns the variable-name string lane.
   */
  fa::string* EffectVariableD3D10::GetName()
  {
    return &name_;
  }

  /**
   * Address: 0x0094C0F0 (FUN_0094C0F0)
   *
   * What it does:
   * D3D10 cube render-target slot keeps an empty body and only owns by-value
   * `shared_ptr` release semantics.
   */
  void EffectVariableD3D10::SetCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget> cubeTarget)
  {
    static_cast<void>(cubeTarget);
  }

  /**
   * Address: 0x0094CD00 (FUN_0094CD00)
   *
   * What it does:
   * Binds a render-target-backed shader-resource view into this effect slot.
   */
  void EffectVariableD3D10::SetRenderTarget(const boost::shared_ptr<RenderTarget> renderTarget)
  {
    ID3D10ShaderResourceView* const shaderResourceView = (renderTarget.get() != nullptr)
      ? static_cast<RenderTargetD3D10*>(renderTarget.get())->GetShaderResourceViewOrThrow()
      : nullptr;
    const HRESULT result = variableHandle_->AsShaderResource()->SetResource(shaderResourceView);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 144, result);
    }
  }

  /**
   * Address: 0x0094CBB0 (FUN_0094CBB0)
   *
   * What it does:
   * Binds a texture shader-resource view into this effect slot.
   */
  void EffectVariableD3D10::SetTexture(const boost::shared_ptr<Texture> texture)
  {
    ID3D10ShaderResourceView* const shaderResourceView =
      (texture.get() != nullptr) ? static_cast<TextureD3D10*>(texture.get())->GetShaderResourceViewOrThrow() : nullptr;
    const HRESULT result = variableHandle_->AsShaderResource()->SetResource(shaderResourceView);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 132, result);
    }
  }

  /**
   * Address: 0x0094C9B0 (FUN_0094C9B0)
   *
   * What it does:
   * Converts to matrix lane and writes one matrix payload.
   */
  void EffectVariableD3D10::SetMatrix4x4(const Matrix* const matrix)
  {
    const HRESULT result = variableHandle_->AsMatrix()->SetMatrix(const_cast<float*>(&matrix->r[0].x));
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 110, result);
    }
  }

  /**
   * Address: 0x0094C310 (FUN_0094C310)
   *
   * What it does:
   * Converts to scalar lane and writes a boolean value.
   */
  void EffectVariableD3D10::SetBool(const bool value)
  {
    const HRESULT result = variableHandle_->AsScalar()->SetBool(value ? TRUE : FALSE);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 60, result);
    }
  }

  /**
   * Address: 0x0094C400 (FUN_0094C400)
   *
   * What it does:
   * Converts to scalar lane and writes an integer value.
   */
  void EffectVariableD3D10::SetInt(const int value)
  {
    const HRESULT result = variableHandle_->AsScalar()->SetInt(value);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 66, result);
    }
  }

  /**
   * Address: 0x0094C4F0 (FUN_0094C4F0)
   *
   * What it does:
   * Converts to scalar lane and writes a float value.
   */
  void EffectVariableD3D10::SetFloat(const float value)
  {
    const HRESULT result = variableHandle_->AsScalar()->SetFloat(value);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 72, result);
    }
  }

  /**
   * Address: 0x0094C5E0 (FUN_0094C5E0)
   *
   * What it does:
   * Converts to vector lane and writes one vector payload.
   */
  void EffectVariableD3D10::SetVector(const float* const value)
  {
    const HRESULT result = variableHandle_->AsVector()->SetFloatVector(const_cast<float*>(value));
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 78, result);
    }
  }

  /**
   * Address: 0x0094C8C0 (FUN_0094C8C0)
   *
   * void const *,int
   *
   * What it does:
   * Writes `byteCount` raw bytes to the variable.
   */
  void EffectVariableD3D10::SetValue(const void* const data, const std::uint32_t byteCount)
  {
    const HRESULT result = variableHandle_->SetRawValue(const_cast<void*>(data), 0U, byteCount);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 103, result);
    }
  }

  /**
   * Address: 0x0094C7D0 (FUN_0094C7D0)
   *
   * int,void const *
   *
   * What it does:
   * Writes `count` floats as raw bytes (`count * 4`).
   */
  void EffectVariableD3D10::SetFloatArray(const std::uint32_t count, const float* const values)
  {
    const HRESULT result = variableHandle_->SetRawValue(const_cast<float*>(values), 0U, count * 4U);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 96, result);
    }
  }

  /**
   * Address: 0x0094CAA0 (FUN_0094CAA0)
   *
   * int,void const *
   *
   * What it does:
   * `AsMatrix()->SetMatrixArray`, handed the address of the `matrices`
   * parameter itself rather than its value (`lea edx, [esp+0xA8]` at
   * 0x0094CAD8; the D3D9 twin passes the pointer). When that fails it falls
   * back to `SetRawValue` with the pointer, but sized as `count` floats
   * (`count * 4` bytes), not `count` matrices. Kept as the binary has it.
   */
  void EffectVariableD3D10::SetMatrixArray(const std::uint32_t count, const Matrix* const matrices)
  {
    auto* const parameterAddress = reinterpret_cast<float*>(const_cast<const Matrix**>(&matrices));
    HRESULT result = variableHandle_->AsMatrix()->SetMatrixArray(parameterAddress, 0U, count);
    if (result < 0) {
      result = variableHandle_->SetRawValue(const_cast<Matrix*>(matrices), 0U, count * 4U);
      if (result < 0) {
        ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 121, result);
      }
    }
  }

  /**
   * Address: 0x0094C6D0 (FUN_0094C6D0)
   *
   * int,unsigned int
   *
   * What it does:
   * `AsVector()->SetFloatVectorArray`, handed the address of the `vectors4`
   * parameter itself rather than its value (`lea edx, [esp+0xA0]` at
   * 0x0094C704) -- the same slip as the D3D9 twin. Nothing in the binary
   * calls the slot.
   */
  void EffectVariableD3D10::SetVectorArray(const std::uint32_t count, const float* const vectors4)
  {
    auto* const parameterAddress = reinterpret_cast<float*>(const_cast<const float**>(&vectors4));
    const HRESULT result = variableHandle_->AsVector()->SetFloatVectorArray(parameterAddress, 0U, count);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 88, result);
    }
  }

  /**
   * Address: 0x0094CE50 (FUN_0094CE50)
   *
   * What it does:
   * Reads a boolean annotation by name from this variable handle.
   */
  bool EffectVariableD3D10::GetAnnotationBool(bool* const outValue, const fa::string& annotationName)
  {
    if (variableHandle_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 154, "invalid effect variable");
    }

    ID3D10EffectVariable* const annotation = variableHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    BOOL boolValue = FALSE;
    const HRESULT result = annotation->AsScalar()->GetBool(&boolValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 164, result);
    }

    *outValue = (boolValue == 1);
    return true;
  }

  /**
   * Address: 0x0094CFE0 (FUN_0094CFE0)
   *
   * What it does:
   * Reads an integer annotation by name from this variable handle.
   */
  bool EffectVariableD3D10::GetAnnotationInt(int* const outValue, const fa::string& annotationName)
  {
    if (variableHandle_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 173, "invalid effect variable");
    }

    ID3D10EffectVariable* const annotation = variableHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    const HRESULT result = annotation->AsScalar()->GetInt(outValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 182, result);
    }

    return true;
  }

  /**
   * Address: 0x0094D150 (FUN_0094D150)
   *
   * What it does:
   * Reads a float annotation by name from this variable handle.
   */
  bool EffectVariableD3D10::GetAnnotationFloat(float* const outValue, const fa::string& annotationName)
  {
    if (variableHandle_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 189, "invalid effect variable");
    }

    ID3D10EffectVariable* const annotation = variableHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    const HRESULT result = annotation->AsScalar()->GetFloat(outValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 198, result);
    }

    return true;
  }

  /**
   * Address: 0x0094D2C0 (FUN_0094D2C0)
   *
   * What it does:
   * Reads a string annotation by name from this variable handle.
   */
  bool EffectVariableD3D10::GetAnnotationString(fa::string* const outValue, const fa::string& annotationName)
  {
    if (variableHandle_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 205, "invalid effect variable");
    }

    ID3D10EffectVariable* const annotation = variableHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    LPCSTR text = nullptr;
    const HRESULT result = annotation->AsString()->GetString(&text);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 215, result);
    }

    outValue->assign_owned((text != nullptr) ? text : "");
    return true;
  }
}

