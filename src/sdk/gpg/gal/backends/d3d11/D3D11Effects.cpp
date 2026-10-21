// FAF addition, not in the shipped binary: the Effects 11 side of the
// Direct3D 11 gal backend (effects, techniques, variables).

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "D3D11Common.h"
#include "DeviceD3D11.h"
#include "EffectD3D11.h"
#include "RenderTargetD3D11.h"
#include "TextureD3D11.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/Matrix.h"

namespace gpg::gal
{
  using d3d11::CheckHresult;
  using d3d11::ThrowError;

  namespace
  {
    [[nodiscard]] DeviceD3D11& ActiveDevice()
    {
      return *static_cast<DeviceD3D11*>(Device::GetInstance());
    }

    [[noreturn]] void ThrowMissing(const char* const file, const int line, const char* const what, const char* const name)
    {
      char message[512]{};
      std::snprintf(message, sizeof(message), "invalid effect %s requested: %s", what, (name != nullptr) ? name : "");
      ThrowError(file, line, message);
    }

    /** Reads one annotation of `owner` (a technique or a variable). */
    template <class Owner, class Read>
    bool ReadAnnotation(Owner* const owner, const msvc8::string& annotationName, Read&& read)
    {
      ID3DX11EffectVariable* const annotation = owner->GetAnnotationByName(annotationName.c_str());
      if (annotation == nullptr || !annotation->IsValid()) {
        return false;
      }
      read(annotation);
      return true;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // EffectD3D11

  EffectD3D11::EffectD3D11(const EffectContext& context, ID3DX11Effect* const effect)
    : mContext(context)
    , mEffect(effect)
  {
    // The wrapper keeps no source once the effect exists (D3D10 empties the
    // copied buffer in `SetEffect`, 0x0094BFE0).
    mContext.mSourceBuffer.Reset();
  }

  EffectD3D11::~EffectD3D11() = default;

  EffectContext* EffectD3D11::GetContext()
  {
    return &mContext;
  }

  void EffectD3D11::GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechnique>>& outTechniques)
  {
    if (mEffect == nullptr) {
      ThrowError("EffectD3D11.cpp", __LINE__, "invalid effect");
    }

    D3DX11_EFFECT_DESC effectDesc{};
    CheckHresult("EffectD3D11.cpp", __LINE__, mEffect->GetDesc(&effectDesc));
    for (UINT index = 0U; index < effectDesc.Techniques; ++index) {
      ID3DX11EffectTechnique* const technique = mEffect->GetTechniqueByIndex(index);
      if (technique == nullptr || !technique->IsValid()) {
        continue;
      }
      D3DX11_TECHNIQUE_DESC techniqueDesc{};
      CheckHresult("EffectD3D11.cpp", __LINE__, technique->GetDesc(&techniqueDesc));
      outTechniques.push_back(
        boost::shared_ptr<EffectTechnique>(new EffectTechniqueD3D11(techniqueDesc.Name, mEffect.Get(), technique))
      );
    }
  }

  boost::shared_ptr<EffectVariable> EffectD3D11::GetVariable(const char* const name)
  {
    if (mEffect == nullptr) {
      ThrowError("EffectD3D11.cpp", __LINE__, "invalid effect");
    }
    ID3DX11EffectVariable* const variable = mEffect->GetVariableByName(name);
    if (variable == nullptr || !variable->IsValid()) {
      ThrowMissing("EffectD3D11.cpp", __LINE__, "variable", name);
    }
    return boost::shared_ptr<EffectVariable>(new EffectVariableD3D11(name, mEffect.Get(), variable));
  }

  boost::shared_ptr<EffectTechnique> EffectD3D11::GetTechnique(const char* const name)
  {
    if (mEffect == nullptr) {
      ThrowError("EffectD3D11.cpp", __LINE__, "invalid effect");
    }
    ID3DX11EffectTechnique* const technique = mEffect->GetTechniqueByName(name);
    if (technique == nullptr || !technique->IsValid()) {
      ThrowMissing("EffectD3D11.cpp", __LINE__, "technique", name);
    }
    return boost::shared_ptr<EffectTechnique>(new EffectTechniqueD3D11(name, mEffect.Get(), technique));
  }

  void EffectD3D11::OnReset() {}

  void EffectD3D11::OnLost() {}

  // ---------------------------------------------------------------------------
  // EffectTechniqueD3D11

  EffectTechniqueD3D11::EffectTechniqueD3D11(
    const char* const name, ID3DX11Effect* const effect, ID3DX11EffectTechnique* const technique
  )
    : mName((name != nullptr) ? name : "")
    , mEffect(effect)
    , mTechnique(technique)
  {
    if (mEffect == nullptr) {
      ThrowError("EffectTechniqueD3D11.cpp", __LINE__, "invalid effect specified");
    }
    // Present when the effect uses the fixed-function vertex emulation
    // (EffectSourceD3D11.h).
    ID3DX11EffectVariable* const viewportSize = mEffect->GetVariableByName("faf_ViewportSize");
    if (viewportSize != nullptr && viewportSize->IsValid()) {
      mViewportSize = viewportSize->AsVector();
    }
  }

  EffectTechniqueD3D11::~EffectTechniqueD3D11() = default;

  msvc8::string* EffectTechniqueD3D11::GetName()
  {
    return &mName;
  }

  int EffectTechniqueD3D11::BeginTechnique()
  {
    if (mTechnique == nullptr) {
      ThrowError("EffectTechniqueD3D11.cpp", __LINE__, "invalid effect technique");
    }

    Device::GetInstance()->BeginTechnique();
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("BeginTechnique %s", mName.c_str());
    }

    D3DX11_TECHNIQUE_DESC desc{};
    CheckHresult("EffectTechniqueD3D11.cpp", __LINE__, mTechnique->GetDesc(&desc));
    mBegun = true;

    // Diagnostics: FAF_GAL_SKIP_TECHNIQUES=";A;B;" draws techniques A and B with no passes.
    static const char* const skipped = std::getenv("FAF_GAL_SKIP_TECHNIQUES");
    if (skipped != nullptr && std::strstr(skipped, (";" + std::string(mName.c_str()) + ";").c_str()) != nullptr) {
      return 0;
    }
    return static_cast<int>(desc.Passes);
  }

  void EffectTechniqueD3D11::EndTechnique()
  {
    if (!mBegun) {
      ThrowError("EffectTechniqueD3D11.cpp", __LINE__, "effect technique begin/end mismatch");
    }
    Device::GetInstance()->EndTechnique();
    mBegun = false;
    if (ActiveDevice().Tracing() && std::getenv("FAF_GAL_TRACE_DUMPS") != nullptr) {
      ActiveDevice().DumpBoundTarget(mName.c_str());
    }
  }

  void EffectTechniqueD3D11::BeginPass(const int pass)
  {
    if (!mBegun) {
      ThrowError("EffectTechniqueD3D11.cpp", __LINE__, "effect technique begin/end mismatch");
    }

    DeviceD3D11& device = ActiveDevice();
    if (mViewportSize != nullptr) {
      D3D11_VIEWPORT viewport{};
      UINT count = 1U;
      device.Immediate()->RSGetViewports(&count, &viewport);
      const float size[4] = {
        viewport.TopLeftX,
        viewport.TopLeftY,
        (viewport.Width > 0.0f) ? 1.0f / viewport.Width : 0.0f,
        (viewport.Height > 0.0f) ? 1.0f / viewport.Height : 0.0f,
      };
      static_cast<void>(mViewportSize->SetFloatVector(size));
    }
    CheckHresult(
      "EffectTechniqueD3D11.cpp",
      __LINE__,
      mTechnique->GetPassByIndex(static_cast<UINT>(pass))->Apply(0U, device.Immediate())
    );
    RecordStateChange();
    D3DX11_PASS_SHADER_DESC vertexShader{};
    D3DX11_EFFECT_SHADER_DESC shaderDesc{};
    if (SUCCEEDED(mTechnique->GetPassByIndex(static_cast<UINT>(pass))->GetVertexShaderDesc(&vertexShader)) &&
        vertexShader.pShaderVariable != nullptr &&
        SUCCEEDED(vertexShader.pShaderVariable->GetShaderDesc(vertexShader.ShaderIndex, &shaderDesc))) {
      device.SetPassVertexShader(shaderDesc.pBytecode, shaderDesc.BytecodeLength);
    }
    D3DX11_STATE_BLOCK_MASK stateMask{};
    static_cast<void>(mTechnique->GetPassByIndex(static_cast<UINT>(pass))->ComputeStateBlockMask(&stateMask));
    device.Pipeline().ApplyOverrides(stateMask.OMBlendState != 0U, stateMask.RSRasterizerState != 0U);
  }

  void EffectTechniqueD3D11::EndPass()
  {
    if (!mBegun) {
      ThrowError("EffectTechniqueD3D11.cpp", __LINE__, "effect technique begin/end mismatch");
    }
  }

  bool EffectTechniqueD3D11::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(mTechnique, annotationName, [&](ID3DX11EffectVariable* const annotation) {
      bool value = false;
      CheckHresult("EffectTechniqueD3D11.cpp", __LINE__, annotation->AsScalar()->GetBool(&value));
      *outValue = value;
    });
  }

  bool EffectTechniqueD3D11::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(mTechnique, annotationName, [&](ID3DX11EffectVariable* const annotation) {
      CheckHresult("EffectTechniqueD3D11.cpp", __LINE__, annotation->AsScalar()->GetInt(outValue));
    });
  }

  bool EffectTechniqueD3D11::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(mTechnique, annotationName, [&](ID3DX11EffectVariable* const annotation) {
      CheckHresult("EffectTechniqueD3D11.cpp", __LINE__, annotation->AsScalar()->GetFloat(outValue));
    });
  }

  bool EffectTechniqueD3D11::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(mTechnique, annotationName, [&](ID3DX11EffectVariable* const annotation) {
      LPCSTR text = nullptr;
      CheckHresult("EffectTechniqueD3D11.cpp", __LINE__, annotation->AsString()->GetString(&text));
      outValue->assign_owned((text != nullptr) ? text : "");
    });
  }

  // ---------------------------------------------------------------------------
  // EffectVariableD3D11

  EffectVariableD3D11::EffectVariableD3D11(
    const char* const name, ID3DX11Effect* const effect, ID3DX11EffectVariable* const variable
  )
    : mName((name != nullptr) ? name : "")
    , mEffect(effect)
    , mVariable(variable)
  {
    if (mEffect == nullptr) {
      ThrowError("EffectVariableD3D11.cpp", __LINE__, "invalid effect specified");
    }
    if (mVariable != nullptr) {
      static_cast<void>(mVariable->GetType()->GetDesc(&mType));
    }
  }

  EffectVariableD3D11::~EffectVariableD3D11() = default;

  msvc8::string* EffectVariableD3D11::GetName()
  {
    return &mName;
  }

  void EffectVariableD3D11::SetCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget> cubeTarget)
  {
    static_cast<void>(cubeTarget);
  }

  void EffectVariableD3D11::SetRenderTarget(const boost::shared_ptr<RenderTarget> renderTarget)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetRenderTarget %p", mName.c_str(), renderTarget.get());
    }
    ID3D11ShaderResourceView* const view =
      (renderTarget != nullptr) ? static_cast<RenderTargetD3D11*>(renderTarget.get())->GetShaderResourceView() : nullptr;
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsShaderResource()->SetResource(view));
    RecordStateChange();
  }

  void EffectVariableD3D11::SetTexture(const boost::shared_ptr<Texture> texture)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetTexture %p", mName.c_str(), texture.get());
    }
    ID3D11ShaderResourceView* const view =
      (texture != nullptr) ? static_cast<TextureD3D11*>(texture.get())->GetShaderResourceView() : nullptr;
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsShaderResource()->SetResource(view));
    RecordStateChange();
  }

  void EffectVariableD3D11::SetMatrix4x4(const Matrix* const matrix)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetMatrix4x4 class %d rows %u cols %u [%g %g %g %g / %g %g %g %g / %g %g %g %g / %g %g %g %g]", mName.c_str(), static_cast<int>(mType.Class), mType.Rows, mType.Columns, matrix->r[0].x, matrix->r[0].y, matrix->r[0].z, matrix->r[0].w, matrix->r[1].x, matrix->r[1].y, matrix->r[1].z, matrix->r[1].w, matrix->r[2].x, matrix->r[2].y, matrix->r[2].z, matrix->r[2].w, matrix->r[3].x, matrix->r[3].y, matrix->r[3].z, matrix->r[3].w);
    }
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsMatrix()->SetMatrix(&matrix->r[0].x));
  }

  void EffectVariableD3D11::SetPackedFloats(const float* const values, const std::uint32_t count, const int line)
  {
    const UINT elements = std::max<UINT>(mType.Elements, 1U);
    switch (mType.Class) {
    case D3D_SVC_SCALAR:
      CheckHresult("EffectVariableD3D11.cpp", line, mVariable->AsScalar()->SetFloatArray(values, 0U, std::min<UINT>(count, elements)));
      return;

    case D3D_SVC_VECTOR: {
      // Effects 11 takes vectors as float4s; D3D9 consumed `Columns` floats
      // per element.
      const UINT columns = std::max<UINT>(mType.Columns, 1U);
      const UINT vectors = std::min<UINT>((count + columns - 1U) / columns, elements);
      std::vector<float> padded(static_cast<std::size_t>(vectors) * 4U, 0.0f);
      for (UINT vector = 0U; vector < vectors; ++vector) {
        for (UINT column = 0U; column < columns && vector * columns + column < count; ++column) {
          padded[vector * 4U + column] = values[vector * columns + column];
        }
      }
      if (mType.Elements == 0U) {
        CheckHresult("EffectVariableD3D11.cpp", line, mVariable->AsVector()->SetFloatVector(padded.data()));
      } else {
        CheckHresult("EffectVariableD3D11.cpp", line, mVariable->AsVector()->SetFloatVectorArray(padded.data(), 0U, vectors));
      }
      return;
    }

    case D3D_SVC_MATRIX_ROWS:
    case D3D_SVC_MATRIX_COLUMNS: {
      // Row-major 4x4 input, as `SetMatrix4x4`.
      const UINT matrices = std::min<UINT>(count / 16U, elements);
      if (matrices != 0U) {
        if (mType.Elements == 0U) {
          CheckHresult("EffectVariableD3D11.cpp", line, mVariable->AsMatrix()->SetMatrix(values));
        } else {
          CheckHresult("EffectVariableD3D11.cpp", line, mVariable->AsMatrix()->SetMatrixArray(values, 0U, matrices));
        }
        return;
      }
      break;
    }

    default:
      break;
    }

    CheckHresult("EffectVariableD3D11.cpp", line, mVariable->SetRawValue(values, 0U, count * 4U));
  }

  void EffectVariableD3D11::SetFloatArray(const std::uint32_t count, const float* const values)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetFloatArray %u class %d el %u", mName.c_str(), count, static_cast<int>(mType.Class), mType.Elements);
    }
    SetPackedFloats(values, count, __LINE__);
  }

  void EffectVariableD3D11::SetVector(const float* const vector4)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetVector %g %g %g %g class %d", mName.c_str(), vector4[0], vector4[1], vector4[2], vector4[3], static_cast<int>(mType.Class));
    }
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsVector()->SetFloatVector(vector4));
  }

  void EffectVariableD3D11::SetValue(const void* const data, const std::uint32_t byteCount)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetValue %u bytes class %d rows %u cols %u el %u", mName.c_str(), byteCount, static_cast<int>(mType.Class), mType.Rows, mType.Columns, mType.Elements);
    }
    // D3D9's SetValue on a numeric float variable converts like SetFloatArray;
    // structs and other types are raw bytes.
    const bool floatNumeric = (mType.Type == D3D_SVT_FLOAT) &&
      (mType.Class == D3D_SVC_SCALAR || mType.Class == D3D_SVC_VECTOR || mType.Class == D3D_SVC_MATRIX_ROWS ||
       mType.Class == D3D_SVC_MATRIX_COLUMNS);
    if (floatNumeric && (byteCount % 4U) == 0U) {
      SetPackedFloats(static_cast<const float*>(data), byteCount / 4U, __LINE__);
      return;
    }
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->SetRawValue(data, 0U, byteCount));
  }

  // D3D9's scalar setters also fill a one-component vector (`float1`, which
  // the effects use for many parameters); Effects 11's AsScalar() refuses one.
  void EffectVariableD3D11::SetFloat(const float value)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetFloat %g class %d", mName.c_str(), value, static_cast<int>(mType.Class));
    }
    if (mType.Class == D3D_SVC_VECTOR) {
      const float vector[4] = {value, value, value, value};
      CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsVector()->SetFloatVector(vector));
      return;
    }
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsScalar()->SetFloat(value));
  }

  void EffectVariableD3D11::SetInt(const int value)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetInt %d", mName.c_str(), value);
    }
    if (mType.Class == D3D_SVC_VECTOR) {
      const int vector[4] = {value, value, value, value};
      CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsVector()->SetIntVector(vector));
      return;
    }
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsScalar()->SetInt(value));
  }

  void EffectVariableD3D11::SetBool(const bool value)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetBool %d", mName.c_str(), value ? 1 : 0);
    }
    if (mType.Class == D3D_SVC_VECTOR) {
      const bool vector[4] = {value, value, value, value};
      CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsVector()->SetBoolVector(vector));
      return;
    }
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsScalar()->SetBool(value));
  }

  void EffectVariableD3D11::SetMatrixArray(const std::uint32_t count, const Matrix* const matrices)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetMatrixArray %u class %d rows %u cols %u el %u", mName.c_str(), count, static_cast<int>(mType.Class), mType.Rows, mType.Columns, mType.Elements);
    }
    // The D3D10 backend passes the address of its `matrices` parameter here
    // (0x0094CAD8); the D3D9 one passes the pointer, which is what is meant.
    CheckHresult(
      "EffectVariableD3D11.cpp", __LINE__, mVariable->AsMatrix()->SetMatrixArray(&matrices->r[0].x, 0U, count)
    );
  }

  void EffectVariableD3D11::SetVectorArray(const std::uint32_t count, const float* const vectors4)
  {
    if (ActiveDevice().Tracing()) {
      ActiveDevice().Trace("var %s SetVectorArray %u", mName.c_str(), count);
    }
    CheckHresult("EffectVariableD3D11.cpp", __LINE__, mVariable->AsVector()->SetFloatVectorArray(vectors4, 0U, count));
  }

  bool EffectVariableD3D11::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(mVariable, annotationName, [&](ID3DX11EffectVariable* const annotation) {
      bool value = false;
      CheckHresult("EffectVariableD3D11.cpp", __LINE__, annotation->AsScalar()->GetBool(&value));
      *outValue = value;
    });
  }

  bool EffectVariableD3D11::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(mVariable, annotationName, [&](ID3DX11EffectVariable* const annotation) {
      CheckHresult("EffectVariableD3D11.cpp", __LINE__, annotation->AsScalar()->GetInt(outValue));
    });
  }

  bool EffectVariableD3D11::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(mVariable, annotationName, [&](ID3DX11EffectVariable* const annotation) {
      CheckHresult("EffectVariableD3D11.cpp", __LINE__, annotation->AsScalar()->GetFloat(outValue));
    });
  }

  bool EffectVariableD3D11::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(mVariable, annotationName, [&](ID3DX11EffectVariable* const annotation) {
      LPCSTR text = nullptr;
      CheckHresult("EffectVariableD3D11.cpp", __LINE__, annotation->AsString()->GetString(&text));
      outValue->assign_owned((text != nullptr) ? text : "");
    });
  }
} // namespace gpg::gal
