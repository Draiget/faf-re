#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")

namespace moho_rtti {

    /**
     * \brief Entry parsed from an input vftable list (type name hint + absolute VA of vftable).
     */
    struct VTableEntry
	{
        /**
         * e.g. "Moho::SPhysBodyConstruct"
         */
        std::string nameHint;

        /**
         * absolute VA in the current process (x86)
         */
        uintptr_t vftableVa;
    };

    /**
     * \brief Namespace emission mode.
     */
    enum class NamespaceMode
	{
        /**
         * Wrap everything into a fixed namespace
         */
        kFixed,

        /**
         * No global wrapper; see flatten_namespaces for class-level formatting
         */
        kNone,

        /**
         * Derive namespaces from demangled type name (e.g., "Moho::A::B::C")
         */
        kDeriveFromType
    };

    /**
     * \brief Code generation options.
     */
    struct DumpOptions
	{
        /**
         * Emit only classes that came from explicit inputs (files/entries).
         * If false, emit everything that was ingested (e.g., from full scan).
         */
        bool emitOnlyInputTypes = true;

        /**
         * Skip classes whose primary vftable has 0 slots.
         */
        bool skipEmptyVftables = true;

        /**
         * Namespace strategy.
         */
        NamespaceMode nsMode = NamespaceMode::kDeriveFromType;

        /**
         * Used only when ns_mode == Fixed.
         */
        std::string fixedNamespace = "moho";

        /**
         * If true, flatten namespaces into a single identifier (Ns1::Ns2::Name -> Ns1_Ns2_Name).
         * If false and ns_mode == DeriveFromType, real nested namespaces will be opened.
         */
        bool flattenNamespaces = false;

        /**
         * If true and ns_mode == DeriveFromType, the first namespace segment is lowercased (Moho->moho).
         */
        bool lowerFirstNamespace = false;

        /**
         * \brief Try to name virtuals from symbols (PDB/exports). If false, keep vf00/vf01...
         */
        bool renameVirtualsWithSymbols = true;

        /**
         * Skip Windows/WinSxS/drivers/etc.
         */
        bool excludeSystemModules = true;

        /**
         * Scan modules in parallel (collect candidates only).
         */
        bool parallelScan = true;

        /**
         * 0 = hardware_concurrency()
         */
        unsigned scanThreads = 0;

        // TypeDescriptor harvesting:
        /**
         * Scan .rdata/.data for ".?A..." strings.
         */
        bool collectTypeDescriptors = true;

        /**
         * Emit class/struct stubs for TDs without vtable.
         */
        bool emitTdStubs = true;

        /**
         * Generate empty primary template stubs (so Base<Args...> is a complete type).
         */
        bool emitTemplateStubs = true;
    };

    /**
     * \brief Set the DbgHelp symbol search path (used for naming virtuals from PDBs).
     */
    void SetSymbolSearchPath(const std::string& path);

    /**
     * \brief Dump RTTI/vftables for the provided entries into a C++ header file.
     */
    bool DumpRtti(
        const std::vector<VTableEntry>& entries,
        const std::string& outHeaderPath
    );

    /**
     * \brief Extended variant with options.
     */
    bool DumpRttiEx(
        const std::vector<VTableEntry>& entries,
        const std::string& outHeaderPath,
        const DumpOptions& opts
    );

    /**
     * \brief Parse a text file with a vftable list and run the dump.
     * Skips empty lines and lines starting with "-", "#", or "//".
     * Accepts formats like:
     *   const Moho::Type::`vftable` 00E29334
     *   Moho::Type 0x00E29334
     *   Moho::Type 00E29334
     */
    bool DumpRttiFromFile(
        const std::string& inputListPath,
        const std::string& outHeaderPath
    );

    /**
     * \brief Parse multiple files and dump (union of all entries).
     */
    bool DumpRttiFromFiles(
        const std::vector<std::string>& inputListPaths,
        const std::string& outHeaderPath,
        const DumpOptions& opts = {}
    );

    /**
     * \brief Scan all loaded modules and dump every valid vftable/type that can be found.
     * (Use when you don't have an input list.)
     */
    bool DumpAllRtti(
        const std::string& outHeaderPath,
        const DumpOptions& optsIn = { /* emit_only_input_types=false is forced inside */ }
    );

    /**
     * \brief Utility: only parse file into entries (for custom uses/tests).
     */
    bool ParseInputFile(
        const std::string& inputListPath,
        std::vector<VTableEntry>& outEntries
    );

} // namespace moho_rtti
