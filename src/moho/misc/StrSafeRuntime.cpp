#include <Windows.h>

#include <cstdarg>
#include <climits>
#include <cstdio>
#include <cwchar>

namespace moho::runtime
{
  namespace
  {
    constexpr HRESULT kHrOk = 0;
    constexpr HRESULT kHrInvalidArg = static_cast<HRESULT>(0x80070057u);
    constexpr HRESULT kHrInsufficientBuffer = static_cast<HRESULT>(0x8007007Au);

  } // namespace

} // namespace moho::runtime
