#pragma once

#include "gpg/core/containers/FastVector.h"
#include "lua/LuaObject.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostUtils.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/containers/TDatList.h"
#include "moho/misc/WeakObject.h"
#include "platform/Platform.h"

namespace moho
{
	class MOHO_EMPTY_BASES CScriptObject :
		public gpg::RObject,
		public WeakObject,
		public boost::noncopyable_::noncopyable,
		public InstanceCounter<CScriptObject>
	{
		MOHO_EBO_PADDING_FIELD(1);

	public:
		/**
		 * Address: 0xA82547
		 * VFTable SLOT: 0
		 */
		[[nodiscard]]
		virtual gpg::RType* GetClass() const = 0;

		/**
		 * Address: 0xA82547
		 * VFTable SLOT: 1
		 */
		virtual gpg::RRef GetDerivedObjectRef() = 0;

		/**
		 * Address: 0x4C6FF0
		 * VFTable SLOT: 2
		 */
		virtual ~CScriptObject() = default;

		/**
		 * Address: 0x4C70A0
		 * VFTable SLOT: 3
		 */
		virtual msvc8::string GetErrorDescription();

		/**
		 * Address: 0x004C70D0
		 */
		void CreateLuaObject(
			const LuaPlus::LuaObject&, 
			const LuaPlus::LuaObject&, 
			const LuaPlus::LuaObject&, 
			const LuaPlus::LuaObject&
		);

		/**
		 * Address: 0x004C72D0
		 */
		void SetLuaObject(const LuaPlus::LuaObject& obj);

		/**
		 * Address: 0x004C7410
		 */
		void LogScriptWarning(CScriptObject*, const char*, const char*);

		/**
		 * Address: 0x004C74B0
		 */
		LuaPlus::LuaObject FindScript(LuaPlus::LuaObject* dest, const char* name);

		/**
		 * Address: 0x004C7580
		 */
		bool RunScriptMultiRet(
			const char* funcName,
			gpg::core::FastVector<LuaPlus::LuaObject>& out,
			LuaPlus::LuaObject arg1,
			LuaPlus::LuaObject arg2, 
			LuaPlus::LuaObject arg3, 
			LuaPlus::LuaObject arg4, 
			LuaPlus::LuaObject arg5
		);

		/**
		 * Address: 0x005FCFE0
		 * @param callback 
		 * @param arg0 
		 */
		void CallbackStr(const char* callback, const char** arg0);

		/**
		 * Address: 0x0067F450
		 *
		 * @param callback 
		 * @param arg0 
		 * @param arg1 
		 */
		void CallbackStr(const char* callback, const char** arg0, const char** arg1);

		/**
		 * Address: 0x006753A0
		 * @param fileName 
		 * @param data 
		 * @param obj 
		 */
		void LuaPCall(const char* fileName, const char** data, LuaPlus::LuaObject* obj);

		/**
		 * Address: 0x00581930
		 * @param fileName 
		 * @param obj 
		 */
		void LuaCall(const char* fileName, LuaPlus::LuaObject* obj);

	public:
		LuaPlus::LuaObject cObject;  // +0x0C (size 0x14)
		LuaPlus::LuaObject mLuaObj;     // +0x20 (size 0x14)
	};

	static_assert(sizeof(CScriptObject) == 0x34, "CScriptObject must be 0x38");
}
