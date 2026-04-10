#include "gpg/core/reflection/RMapStringFloatTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <map>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/String.h"

namespace
{
  using TypeInfo = gpg::RMapStringFloatTypeInfo;

  alignas(TypeInfo) unsigned char gMapStringFloatTypeInfoStorage[sizeof(TypeInfo)];
  bool gMapStringFloatTypeInfoConstructed = false;
  msvc8::string gMapStringFloatTypeName{};
  std::uint32_t gMapStringFloatTypeNameInitGuard = 0u;

  [[nodiscard]] TypeInfo& AcquireMapStringFloatTypeInfo()
  {
    if (!gMapStringFloatTypeInfoConstructed) {
      new (gMapStringFloatTypeInfoStorage) TypeInfo();
      gMapStringFloatTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gMapStringFloatTypeInfoStorage);
  }

  /**
   * Address: 0x00BFDAC0 (FUN_00BFDAC0)
   *
   * What it does:
   * Releases cached lexical storage for `gpg::RMapType_string_float::GetName`.
   */
  void cleanup_MapStringFloat_TypeName()
  {
    gMapStringFloatTypeName.clear();
    gMapStringFloatTypeNameInitGuard = 0u;
  }

  void CleanupMapStringFloatTypeInfoAtExit()
  {
    gpg::cleanup_MapStringFloat_Type();
  }

  struct MapStringFloatTypeInfoBootstrap
  {
    MapStringFloatTypeInfoBootstrap()
    {
      (void)gpg::register_MapStringFloat_Type_AtExit();
    }
  };

  [[maybe_unused]] MapStringFloatTypeInfoBootstrap gMapStringFloatTypeInfoBootstrap;
} // namespace

namespace gpg
{
  /**
   * Address: 0x006AE290 (FUN_006AE290, gpg::RMapType_string_float::GetName)
   *
   * What it does:
   * Builds/caches the lexical map type label from runtime key/value RTTI
   * names and returns `"map<key,value>"`.
   */
  const char* RMapStringFloatTypeInfo::GetName() const
  {
    if ((gMapStringFloatTypeNameInitGuard & 1u) == 0u) {
      gMapStringFloatTypeNameInitGuard |= 1u;

      gpg::RType* keyType = gpg::LookupRType(typeid(std::string));
      if (keyType == nullptr) {
        keyType = gpg::LookupRType(typeid(msvc8::string));
      }

      gpg::RType* valueType = gpg::LookupRType(typeid(float));
      const char* const keyName = keyType != nullptr ? keyType->GetName() : "std::string";
      const char* const valueName = valueType != nullptr ? valueType->GetName() : "float";

      gMapStringFloatTypeName = gpg::STR_Printf("map<%s,%s>", keyName, valueName);
      (void)std::atexit(&cleanup_MapStringFloat_TypeName);
    }

    return gMapStringFloatTypeName.c_str();
  }

  /**
   * Address: 0x006AE370 (FUN_006AE370, gpg::RMapType_string_float::GetLexical)
   *
   * What it does:
   * Formats inherited lexical text and appends current map element count.
   */
  msvc8::string RMapStringFloatTypeInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    const auto* const map = static_cast<const std::map<std::string, float>*>(ref.mObj);
    const int size = map ? static_cast<int>(map->size()) : 0;
    return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
  }

  /**
   * Address: 0x006AF250 (FUN_006AF250, gpg::RMapType_string_float::SerLoad)
   *
   * What it does:
   * Clears destination storage, then reads `count` serialized
   * `string -> float` pairs from the archive.
   */
  void RMapStringFloatTypeInfo::SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const destination = reinterpret_cast<std::map<std::string, float>*>(objectPtr);
    unsigned int count = 0u;
    archive->ReadUInt(&count);

    destination->clear();
    for (unsigned int index = 0u; index < count; ++index) {
      msvc8::string key{};
      float value = 0.0f;
      archive->ReadString(&key);
      archive->ReadFloat(&value);
      (*destination)[key.c_str()] = value;
    }
  }

  /**
   * Address: 0x006AF390 (FUN_006AF390, gpg::RMapType_string_float::SerSave)
   *
   * What it does:
   * Writes map size followed by each key/value pair in map-order.
   */
  void RMapStringFloatTypeInfo::SerSave(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const source = reinterpret_cast<const std::map<std::string, float>*>(objectPtr);
    const unsigned int count = source != nullptr ? static_cast<unsigned int>(source->size()) : 0u;
    archive->WriteUInt(count);

    if (source == nullptr) {
      return;
    }

    for (const auto& entry : *source) {
      msvc8::string key(entry.first.c_str());
      archive->WriteString(&key);
      archive->WriteFloat(entry.second);
    }
  }

  /**
   * Address: 0x006AE350 (FUN_006AE350, gpg::RMapType_string_float::Init)
   *
   * What it does:
   * Sets map size/version metadata and binds map serializer callbacks.
   */
  void RMapStringFloatTypeInfo::Init()
  {
    size_ = 0x0C;
    version_ = 1;
    serLoadFunc_ = &RMapStringFloatTypeInfo::SerLoad;
    serSaveFunc_ = &RMapStringFloatTypeInfo::SerSave;
  }

  /**
   * Address: 0x006B16B0 (FUN_006B16B0, register_MapStringFloat_Type_00)
   */
  gpg::RType* register_MapStringFloat_Type_00()
  {
    TypeInfo& typeInfo = AcquireMapStringFloatTypeInfo();
    gpg::PreRegisterRType(typeid(std::map<std::string, float>), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFDBE0 (FUN_00BFDBE0, cleanup_MapStringFloat_Type)
   */
  void cleanup_MapStringFloat_Type()
  {
    if (!gMapStringFloatTypeInfoConstructed) {
      return;
    }

    AcquireMapStringFloatTypeInfo().~RMapStringFloatTypeInfo();
    gMapStringFloatTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD6BC0 (FUN_00BD6BC0, register_MapStringFloat_Type_AtExit)
   */
  int register_MapStringFloat_Type_AtExit()
  {
    (void)register_MapStringFloat_Type_00();
    return std::atexit(&CleanupMapStringFloatTypeInfoAtExit);
  }
} // namespace gpg
