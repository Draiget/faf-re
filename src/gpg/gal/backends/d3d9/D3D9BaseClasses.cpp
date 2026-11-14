// The abstract base classes' out-of-line members. Nothing here uses Direct3D 9, so the Vulkan
// backend links this file too (the Linux client, issue #255).
#include "gpg/gal/CubeRenderTarget.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/PipelineState.hpp"
#include "gpg/gal/RenderTarget.hpp"

namespace gpg::gal
{

  /**
   * Address: 0x008F3820 (FUN_008F3820)
   *
   * What it does:
   * Installs the abstract technique vtable.
   */
  EffectTechnique::EffectTechnique() = default;

  /**
   * Address: 0x008F3810 (FUN_008F3810)
   *
   * What it does:
   * Reinstalls the abstract technique vtable (`mov [ecx], 0x00D42CA0;
   * ret`). Both backend destructors inline it; this out-of-line copy is
   * what the backend constructors' unwind funclets jump to (0x00B5A083,
   * 0x00B5A0AE, 0x00B5B453, 0x00B5B476).
   */
  EffectTechnique::~EffectTechnique() = default;

  /**
   * Address: 0x008F4B80 (FUN_008F4B80)
   *
   * What it does:
   * Installs the abstract index-buffer vtable.
   */
  IndexBuffer::IndexBuffer() = default;

  /**
   * Address: 0x008F4B70
   *
   * What it does:
   * Reinstalls the abstract index-buffer vtable (`mov [ecx], 0x00D42D98;
   * ret`). Both backend destructors inline it; this out-of-line copy is for
   * their unwind paths, and IDA never boxed it as a function.
   */
  IndexBuffer::~IndexBuffer() = default;

  /**
   * Address: 0x008F5250 (FUN_008F5250)
   *
   * What it does:
   * Installs the abstract render-target vtable.
   */
  RenderTarget::RenderTarget() = default;

  /**
   * What it does:
   * Reinstalls the abstract render-target vtable. Both derived destructors
   * inline it (0x008F53F1, 0x00902EF1).
   */
  RenderTarget::~RenderTarget() = default;

  /**
   * Address: 0x008F7F20 (FUN_008F7F20)
   *
   * What it does:
   * Installs the abstract cube-render-target vtable.
   */
  CubeRenderTarget::CubeRenderTarget() = default;

  /**
   * What it does:
   * Reinstalls the abstract cube-render-target vtable. The derived
   * destructors inline it (0x008F8068 in `CubeRenderTargetD3D10`).
   */
  CubeRenderTarget::~CubeRenderTarget() = default;

  /**
   * Address: 0x00902240 (FUN_00902240)
   *
   * What it does:
   * Installs the abstract pipeline-state vtable and returns `this`. Both
   * backend constructors inline it.
   */
  PipelineState::PipelineState() = default;

  /**
   * Address: 0x00902230 (FUN_00902230)
   *
   * What it does:
   * Reinstalls the abstract pipeline-state vtable (`mov [ecx], 0x00D436F0;
   * ret` - no `this` in eax, so this is the destructor, not the constructor
   * it used to be annotated as). Called from both backends' pipeline-state
   * constructor unwind paths and destructors (0x00949F80 and 0x00946BE0 on
   * D3D9, 0x00902CA0 and 0x009023F0 on D3D10).
   */
  PipelineState::~PipelineState() = default;
  namespace
  {
  } // namespace

} // namespace gpg::gal
