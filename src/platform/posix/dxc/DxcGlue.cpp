// Engine addition (issue #255): see DxcGlue.h. Compiled without the POSIX <Windows.h>: the Win32
// names here are DXC's own (dxc/WinAdapter.h, through dxc/dxcapi.h).

#include "platform/posix/dxc/DxcGlue.h"

#include <cstdio>
#include <mutex>

#include <dlfcn.h>

#include <dxc/dxcapi.h>

namespace
{
  struct Library
  {
    void* signer = nullptr;    // libdxil.so
    void* compiler = nullptr;  // libdxcompiler.so
    DxcCreateInstanceProc create = nullptr;
  };

  Library gLibrary;
  std::mutex gLoadMutex;

  // A compiler and utils object per thread, as on Windows: one object must not be used by two
  // threads at once, separate ones compile in parallel.
  struct ThreadDxc
  {
    CComPtr<IDxcUtils> utils;
    CComPtr<IDxcCompiler3> dxc;
  };

  ThreadDxc* ThisThreadDxc()
  {
    thread_local ThreadDxc instance;
    thread_local bool tried = false;
    if (!tried && gLibrary.create != nullptr) {
      tried = true;
      if (FAILED(gLibrary.create(CLSID_DxcUtils, IID_PPV_ARGS(&instance.utils))) ||
          FAILED(gLibrary.create(CLSID_DxcCompiler, IID_PPV_ARGS(&instance.dxc)))) {
        instance.utils.Release();
        instance.dxc.Release();
      }
    }
    return instance.dxc != nullptr ? &instance : nullptr;
  }

  platform::posix::dxc::Output Run(
    const std::string_view source, const std::vector<std::wstring>& arguments, const bool preprocessed
  )
  {
    platform::posix::dxc::Output output;
    ThreadDxc* const dxc = ThisThreadDxc();
    if (dxc == nullptr) {
      output.messages = gLibrary.create == nullptr ? "libdxcompiler.so is not loaded" : "DxcCreateInstance failed on this thread";
      return output;
    }
    std::vector<LPCWSTR> pointers;
    pointers.reserve(arguments.size());
    for (const std::wstring& argument : arguments) {
      pointers.push_back(argument.c_str());
    }
    DxcBuffer buffer{};
    buffer.Ptr = source.data();
    buffer.Size = source.size();
    buffer.Encoding = DXC_CP_UTF8;

    CComPtr<IDxcResult> result;
    const HRESULT hr = dxc->dxc->Compile(
      &buffer, pointers.data(), static_cast<UINT32>(pointers.size()), nullptr, IID_PPV_ARGS(&result)
    );
    if (FAILED(hr) || result == nullptr) {
      char message[64]{};
      std::snprintf(message, sizeof(message), "IDxcCompiler3::Compile failed (0x%08X)", static_cast<unsigned>(hr));
      output.messages = message;
      return output;
    }
    CComPtr<IDxcBlobUtf8> errors;
    if (SUCCEEDED(result->GetOutput(DXC_OUT_ERRORS, IID_PPV_ARGS(&errors), nullptr)) && errors != nullptr &&
        errors->GetStringLength() != 0U) {
      output.messages.assign(errors->GetStringPointer(), errors->GetStringLength());
    }
    HRESULT status = E_FAIL;
    result->GetStatus(&status);
    if (FAILED(status)) {
      return output;
    }
    if (preprocessed) {
      CComPtr<IDxcBlobUtf8> text;
      if (FAILED(result->GetOutput(DXC_OUT_HLSL, IID_PPV_ARGS(&text), nullptr)) || text == nullptr) {
        output.messages += "\nno preprocessed source produced";
        return output;
      }
      output.text.assign(text->GetStringPointer(), text->GetStringLength());
    } else {
      CComPtr<IDxcBlob> object;
      if (FAILED(result->GetOutput(DXC_OUT_OBJECT, IID_PPV_ARGS(&object), nullptr)) || object == nullptr) {
        output.messages += "\nno object produced";
        return output;
      }
      const auto* const bytes = static_cast<const unsigned char*>(object->GetBufferPointer());
      output.object.assign(bytes, bytes + object->GetBufferSize());
    }
    output.succeeded = true;
    return output;
  }

  std::wstring Widen(const std::string_view text)
  {
    // Arguments and names are ASCII (entry points, profiles, macro names, VFS paths).
    std::wstring wide;
    wide.reserve(text.size());
    for (const char c : text) {
      wide.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    return wide;
  }
} // namespace

std::string platform::posix::dxc::Load(const std::vector<std::string>& directories, std::string& version)
{
  const std::lock_guard<std::mutex> lock(gLoadMutex);
  if (gLibrary.create != nullptr) {
    return {};
  }
  std::vector<std::string> candidates;
  for (std::string directory : directories) {
    if (!directory.empty() && directory.back() != '/') {
      directory += '/';
    }
    candidates.push_back(directory);
  }
  candidates.emplace_back();  // the system's library path
  for (const std::string& directory : candidates) {
    // The signer first, by path, so libdxcompiler's own dlopen("libdxil.so") finds it.
    gLibrary.signer = ::dlopen((directory + "libdxil.so").c_str(), RTLD_NOW | RTLD_GLOBAL);
    gLibrary.compiler = ::dlopen((directory + "libdxcompiler.so").c_str(), RTLD_NOW);
    if (gLibrary.compiler != nullptr) {
      break;
    }
    if (gLibrary.signer != nullptr) {
      ::dlclose(gLibrary.signer);
      gLibrary.signer = nullptr;
    }
  }
  if (gLibrary.compiler == nullptr) {
    return "libdxcompiler.so not found next to the executable, in FAF_DXC_DIR or on the library path";
  }
  const auto create = reinterpret_cast<DxcCreateInstanceProc>(::dlsym(gLibrary.compiler, "DxcCreateInstance"));
  CComPtr<IDxcCompiler3> probe;
  if (create == nullptr || FAILED(create(CLSID_DxcCompiler, IID_PPV_ARGS(&probe)))) {
    ::dlclose(gLibrary.compiler);
    gLibrary.compiler = nullptr;
    if (gLibrary.signer != nullptr) {
      ::dlclose(gLibrary.signer);
      gLibrary.signer = nullptr;
    }
    return "libdxcompiler.so does not provide IDxcCompiler3";
  }
  CComPtr<IDxcVersionInfo> versionInfo;
  UINT32 major = 0U;
  UINT32 minor = 0U;
  if (SUCCEEDED(probe->QueryInterface(IID_PPV_ARGS(&versionInfo))) && SUCCEEDED(versionInfo->GetVersion(&major, &minor))) {
    char text[64]{};
    std::snprintf(text, sizeof(text), "dxc %u.%u%s", major, minor, gLibrary.signer != nullptr ? " signed" : " unsigned");
    version = text;
  } else {
    version = "dxc";
  }
  gLibrary.create = create;
  return {};
}

bool platform::posix::dxc::Loaded()
{
  return gLibrary.create != nullptr;
}

platform::posix::dxc::Output platform::posix::dxc::Compile(
  const std::string_view source, const std::vector<std::wstring>& arguments
)
{
  return Run(source, arguments, false);
}

platform::posix::dxc::Output platform::posix::dxc::Preprocess(
  const std::string_view source, const std::string_view sourceName, const std::vector<std::pair<std::string, std::string>>& defines
)
{
  std::vector<std::wstring> arguments{Widen(sourceName), L"-P"};
  for (const auto& [name, value] : defines) {
    arguments.push_back(L"-D");
    arguments.push_back(value.empty() ? Widen(name) : Widen(name) + L"=" + Widen(value));
  }
  return Run(source, arguments, true);
}
