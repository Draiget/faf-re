#include "moho/misc/TreeData.h"

#include <new>

namespace moho
{
  /**
   * Address: 0x004D6F00 (FUN_004D6F00)
   *
   * What it does:
   * Initializes one tree-item payload from one watch snapshot.
   */
  TreeData::TreeData(const ScrWatch& watch)
    : wxTreeItemDataRuntime()
    , mWatch(watch.name, watch.obj)
  {
    mPayload = nullptr;
  }

  /**
   * Address: 0x004D6F70 (FUN_004D6F70)
   *
   * What it does:
   * Releases embedded watch lanes and returns to wx client-data base state.
   */
  TreeData::~TreeData()
  {
    ResetClientDataBaseVTable();
  }

  /**
   * Address: 0x004D6FC0 (FUN_004D6FC0)
   *
   * What it does:
   * Implements deleting-dtor thunk semantics for one watch tree payload.
   */
  TreeData* TreeData::DeleteWithFlag(TreeData* const object, const std::uint8_t deleteFlags) noexcept
  {
    if (object == nullptr) {
      return nullptr;
    }

    object->~TreeData();
    if ((deleteFlags & 1u) != 0u) {
      operator delete(object);
    }
    return object;
  }
} // namespace moho

