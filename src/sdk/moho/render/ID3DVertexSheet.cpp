#include "ID3DVertexSheet.h"

#include "boost/shared_ptr.h"

#include <new>

namespace moho
{
  /**
   * Address: 0x00813D90 (FUN_00813D90, boost::shared_ptr_ID3DVertexSheet::shared_ptr_ID3DVertexSheet)
   * Address: 0x007FF580 (FUN_007FF580, second independent emission of the
   * same `shared_ptr<ID3DVertexSheet>(ID3DVertexSheet*)` constructor --
   * identical inline `sp_counted_impl_p<ID3DVertexSheet>` construction plus
   * retain/release-old and refcount-settle shape, reached from a different
   * call site (`Moho::WRenViewport`'s vtable neighbourhood, via
   * FUN_007FF4C0) than the one above)
   *
   * What it does:
   * Constructs one `shared_ptr<ID3DVertexSheet>` from one raw vertex-sheet pointer lane.
   */
  boost::shared_ptr<ID3DVertexSheet>* ConstructSharedVertexSheetFromRaw(
    boost::shared_ptr<ID3DVertexSheet>* const outVertexSheet,
    ID3DVertexSheet* const vertexSheet
  )
  {
    return ::new (outVertexSheet) boost::shared_ptr<ID3DVertexSheet>(vertexSheet);
  }

  /**
   * Address: 0x00814940 (FUN_00814940, boost::shared_ptr_ID3DVertexSheet::operator=)
   *
   * What it does:
   * Rebinds one `shared_ptr<ID3DVertexSheet>` from a raw pointer and releases
   * prior ownership.
   */
  boost::shared_ptr<ID3DVertexSheet>* AssignSharedVertexSheetFromRaw(
    boost::shared_ptr<ID3DVertexSheet>* const outVertexSheet,
    ID3DVertexSheet* const vertexSheet
  )
  {
    outVertexSheet->reset(vertexSheet);
    return outVertexSheet;
  }

  /**
   * Address: 0x00440020 (FUN_00440020, sub_440020)
   *
   * What it does:
   * Initializes the base interface vftable lane for derived vertex sheets.
   */
  ID3DVertexSheet::ID3DVertexSheet() = default;

  /**
   * Address: 0x0043CD10 (FUN_0043CD10, ID3DVertexSheet dtor body)
   * Address: 0x0043CD20 (FUN_0043CD20, sub_43CD20, scalar deleting destructor thunk)
   *
   * What it does:
   * Defaulted destructor body — compiler emits a 2-insn vtable-set + retn at
   * 0x0043CD10 and a separate scalar-deleting thunk at 0x0043CD20.
   */
  ID3DVertexSheet::~ID3DVertexSheet() = default;
} // namespace moho
