#pragma once

// Engine addition (issue #255): the part of <d3d11.h> the Linux client uses. The Vulkan backend
// shares the Direct3D 11 vertex layouts (gpg/gal/backends/d3d11/D3D11VertexLayouts.cpp), which are
// tables of D3D11_INPUT_ELEMENT_DESC; Linux has no Direct3D 11 itself. Fields have the Windows
// types and order; the formats are DXGI's (DirectX-Headers' <dxgiformat.h>).

#if defined(_WIN32)
#error "platform/posix/win32/d3d11.h is for builds without the Windows SDK"
#endif

#include <dxgiformat.h>

#include <Windows.h>

enum D3D11_INPUT_CLASSIFICATION
{
  D3D11_INPUT_PER_VERTEX_DATA = 0,
  D3D11_INPUT_PER_INSTANCE_DATA = 1
};

struct D3D11_INPUT_ELEMENT_DESC
{
  const char* SemanticName;
  UINT SemanticIndex;
  DXGI_FORMAT Format;
  UINT InputSlot;
  UINT AlignedByteOffset;
  D3D11_INPUT_CLASSIFICATION InputSlotClass;
  UINT InstanceDataStepRate;
};

#define D3D11_APPEND_ALIGNED_ELEMENT 0xffffffffu
