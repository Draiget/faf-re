// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/BitArray2D.h"
#include "gpg/core/containers/Rect2.h"

namespace gpg::HaStar
{
    /**
     * VFTABLE: 0x00D47810
     * COL:  0x00E52D78
     */
    class ICache {
    public:
        /**
         * Address: 0x009315C0 (FUN_009315C0)
         *
         * What it does:
         * Initializes one `ICache` interface object by binding its vtable.
         */
        ICache();

        /**
         * Address: 0x00A82547
         * Slot: 0
         * Demangled: _purecall
         */
        virtual void Unknown() = 0;
    };

    struct OccupationData
    {
        std::uint32_t mWords[5];
    };

    class Cluster
    {
    public:
        /**
         * Cluster node coordinate: one `(x, z)` cell pair packed into two
         * bytes. Trailing storage in `Data` is laid out as
         * `Node[nodeCount]` followed by `Edge[nodeCount*(nodeCount-1)/2]`.
         */
        struct Node
        {
            std::uint8_t x;
            std::uint8_t z;
        };
        static_assert(sizeof(Node) == 0x02, "Cluster::Node size must be 0x02");

        /**
         * Cluster edge bucket: one quantized `QuantizeEdgeCost` bucket value
         * packed into a single byte. Stored as a triangular matrix indexed via
         * `lhs + (rhs*(rhs-1))/2` (`TriangularEdgePairIndex`).
         */
        struct Edge
        {
            std::int8_t cost;
        };
        static_assert(sizeof(Edge) == 0x01, "Cluster::Edge size must be 0x01");

        /**
         * Refcounted cluster payload. Header layout:
         *   +0x00 mRefs          intrusive refcount
         *   +0x04 mReleaseObject  dispose-callback object (nullable)
         *   +0x08 mReleaseArg    dispose-callback argument
         *   +0x0C mNodeCount     trailing-array element count
         *   +0x0D mNodes[]       followed by edges (allocated inline)
         */
        struct Data
        {
            std::int32_t mRefs;        // +0x00
            void* mReleaseObject;      // +0x04
            std::uint32_t mReleaseArg; // +0x08
            std::uint8_t mNodeCount;   // +0x0C
            Node mNodes[1];            // +0x0D flexible tail
        };
        static_assert(offsetof(Data, mNodeCount) == 0x0C, "Cluster::Data::mNodeCount offset must be 0x0C");
        static_assert(offsetof(Data, mNodes) == 0x0D, "Cluster::Data::mNodes offset must be 0x0D");

        Data* mData{};

        Cluster() = default;

        /**
         * Address: 0x00765840 (FUN_00765840, ??0Cluster@HaStar@gpg@@QAE@ABV012@@Z)
         *
         * What it does:
         * Copy-constructs a cluster handle and retains its shared data.
         */
        Cluster(const Cluster& other);

        /**
         * Address: 0x008E3450 (FUN_008E3450, ??4Cluster@HaStar@gpg@@QAEAAV012@ABV012@@Z)
         *
         * What it does:
         * Assigns cluster shared-data with intrusive refcount ownership updates.
         */
        Cluster& operator=(const Cluster& other);

        /**
         * Address: 0x00765860 (FUN_00765860, ??1Cluster@HaStar@gpg@@QAE@XZ)
         *
         * What it does:
         * Releases a cluster shared-data reference and destroys it when refcount hits zero.
         */
        ~Cluster();

        /**
         * Address: 0x0092D8B0 (FUN_0092D8B0, ?QuantizeEdgeCost@Cluster@HaStar@gpg@@SAMMM@Z)
         *
         * What it does:
         * Quantizes one edge-cost ratio into a 0..31 bucket using
         * `ceil(ln(a / b) * 6)`.
         */
        [[nodiscard]] static float QuantizeEdgeCost(float a, float b);

        /**
         * Address: 0x00954110 (FUN_00954110,
         * ?SetData@Cluster@HaStar@gpg@@QAEXPBUNode@123@PBUEdge@123@I@Z)
         *
         * IDA signature:
         * void __thiscall SetData(
         *   gpg::HaStar::Cluster *this@<ecx>,
         *   const Node *nodes, const Edge *edges, unsigned int nodeCount);
         *
         * What it does:
         * Replaces the cluster's shared payload. When the current payload has
         * a different node count or is aliased, allocates a fresh
         * `Data + Node[n] + Edge[n*(n-1)/2]` block and drops the previous
         * reference (invoking its dispose-callback when refcount hits zero).
         * Then copies `nodeCount` nodes and `nodeCount*(nodeCount-1)/2` edge
         * buckets into the trailing storage. Asserts `nodeCount < 256`.
         */
        void SetData(const Node* nodes, const Edge* edges, unsigned int nodeCount);
    };

    struct SubclusterData
    {
        Cluster mClusters[16];
        std::int32_t mLevel;
    };

    struct Subcluster
    {
        Cluster* mArray;
        std::int32_t mWidth;
        std::int32_t mHeight;

        /**
         * Address: 0x008E3420 (FUN_008E3420, ??0struct_Subcluster@@QAE@@Z)
         *
         * What it does:
         * Initializes an empty subcluster grid.
         */
        Subcluster();

        /**
         * Address: 0x008E36C0 (FUN_008E36C0, ??0struct_Subcluster@@QAE@HH@Z)
         *
         * What it does:
         * Allocates and default-initializes a width x height cluster grid.
         */
        Subcluster(int width, int height);

        /**
         * Address: 0x0076BF30 (FUN_0076BF30, ??1struct_Subcluster@@QAE@@Z)
         *
         * What it does:
         * Destroys all cluster elements and releases the backing array.
         */
        ~Subcluster();

        /**
         * Address: 0x008E3C80 (FUN_008E3C80)
         *
         * What it does:
         * Reinitializes storage for a new width x height cluster grid by
         * destroying any existing storage and constructing a fresh array.
         */
        void ResetStorage(int width, int height);
    };

    class IOccupationSource
    {
    public:
        virtual void GetOccupationData(int worldX, int worldY, OccupationData& outData) = 0;
    };

    /**
     * Address: 0x0076B8B0 (FUN_0076B8B0)
     *
     * IOccupationSource *
     *
     * IDA signature:
     * _DWORD *__usercall sub_76B8B0@<eax>(_DWORD *result@<eax>)
     *
     * What it does:
     * Writes the `IOccupationSource` vtable pointer into one object lane and
     * returns the same object pointer.
     */
    [[nodiscard]] IOccupationSource* InitializeOccupationSourceVTableCloneA(IOccupationSource* source);

    /**
     * Address: 0x0076CB70 (FUN_0076CB70)
     *
     * IOccupationSource *
     *
     * IDA signature:
     * _DWORD *__usercall sub_76CB70@<eax>(_DWORD *result@<eax>)
     *
     * What it does:
     * Clone entry that writes the same `IOccupationSource` vtable pointer into
     * one object lane and returns that object pointer.
     */
    [[nodiscard]] IOccupationSource* InitializeOccupationSourceVTableCloneB(IOccupationSource* source);

    struct ClusterCache
    {
        void* mCacheTree{};
        void* mCacheRefs{};

        /**
         * Address: 0x00931FB0 (FUN_00931FB0, ??1WeakPtr_ClusterCache@Moho@@QAE@@Z)
         *
         * What it does:
         * Releases the shared cache control block reference.
         */
        ~ClusterCache();

        /**
         * Address: 0x00935420 (FUN_00935420,
         * ?FetchCluster@ClusterCache@HaStar@gpg@@QAE?AVCluster@23@ABUOccupationData@23@@Z)
         *
         * What it does:
         * Returns or builds a cluster from raw occupation data.
         */
        [[nodiscard]] Cluster FetchCluster(const OccupationData& occupationData);

        /**
         * Address: 0x00935450 (FUN_00935450,
         * ?FetchCluster@ClusterCache@HaStar@gpg@@QAE?AVCluster@23@ABUSubclusterData@23@@Z)
         *
         * What it does:
         * Returns or builds a cluster from 4x4 child clusters at the lower level.
         */
        [[nodiscard]] Cluster FetchCluster(const SubclusterData& subclusterData);
    };

    /**
     * Address: 0x009552D0 (FUN_009552D0,
     * ?ClusterBuild@HaStar@gpg@@YA?AVCluster@12@ABUOccupationData@12@@Z)
     *
     * What it does:
     * Builds a cluster payload from occupancy cell data.
     */
    [[nodiscard]] Cluster ClusterBuild(const OccupationData& occupationData);

    /**
     * Address: 0x009310E0 (FUN_009310E0,
     * ?ClusterBuild@HaStar@gpg@@YA?AVCluster@12@ABUSubclusterData@12@@Z)
     *
     * What it does:
     * Builds a cluster payload from 4x4 lower-level child clusters.
     */
    [[nodiscard]] Cluster ClusterBuild(const SubclusterData& subclusterData);

    /**
     * Address: 0x009542D0 (FUN_009542D0,
     * ?ClusterRect@HaStar@gpg@@YA?AV?$Rect2@H@2@HHEHH@Z_0)
     *
     * What it does:
     * Computes one cluster-aligned world rectangle for `(x,z)` and clamps it
     * against per-axis cluster bounds.
     */
    [[nodiscard]] gpg::Rect2i ClusterRect(
        int worldX,
        int worldZ,
        std::uint8_t level,
        int maxClusterX,
        int maxClusterZ
    );

    /**
     * Address: 0x00954340 (FUN_00954340,
     * ?ClusterIndexRect@HaStar@gpg@@YA?AV?$Rect2@H@2@HHEHH@Z)
     *
     * What it does:
     * Computes one clamped cluster-index rectangle from world-space `(x,z)`
     * coordinates, level shift, and per-axis cluster limits.
     */
    [[nodiscard]] gpg::Rect2i ClusterIndexRect(
        int worldX,
        int worldZ,
        std::uint8_t level,
        int maxClusterX,
        int maxClusterZ
    );

    class ClusterMap
    {
    public:
        /**
         * Address: 0x008E3CD0 (FUN_008E3CD0,
         * ??0ClusterMap@HaStar@gpg@@QAE@PAUIOccupationSource@12@IIABVClusterCache@12@IABV?$Rect2@H@2@@Z)
         *
         * What it does:
         * Initializes hierarchy levels/check-bit arrays for path-cluster background rebuilds.
         */
        ClusterMap(
            IOccupationSource* source,
            unsigned int widthM,
            unsigned int heightM,
            const ClusterCache& cache,
            unsigned int numLevels,
            const gpg::Rect2i& area
        );

        /**
         * Address: 0x0076BB60 (FUN_0076BB60, ??1ClusterMap@HaStar@gpg@@QAE@@Z)
         *
         * What it does:
         * Releases hierarchy/check-bit resources and cache weak/shared reference state.
         */
        ~ClusterMap();

        /**
         * Address: 0x008E33E0 (FUN_008E33E0,
         * ?ClusterIndexRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@HHE@Z)
         *
         * What it does:
         * Converts one world-space cell `(x,z)` into the corresponding
         * clamped cluster-index rectangle for the requested level.
         */
        [[nodiscard]] gpg::Rect2i ClusterIndexRect(int worldX, int worldZ, std::uint8_t level) const;

        /**
         * Address: 0x008E3530 (FUN_008E3530,
         * ?ClusterRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@ABV43@E@Z)
         *
         * What it does:
         * Expands one world-space rectangle to cluster-aligned world bounds for
         * the requested level and clamps to map dimensions.
         */
        [[nodiscard]] gpg::Rect2i ClusterRect(const gpg::Rect2i& worldRect, std::uint8_t level) const;

        /**
         * Address: 0x008E35A0 (FUN_008E35A0,
         * ?ClusterIndexRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@ABV43@E@Z)
         * Alt binary: 0x10035650 (FUN_10035650, ?...@Z_0)
         *
         * What it does:
         * Converts a world-space rectangle into clamped cluster-index bounds
         * for the requested path level.
         */
        [[nodiscard]] gpg::Rect2i ClusterIndexRect(const gpg::Rect2i& worldRect, std::uint8_t level) const;

        /**
         * Address: 0x100356F0 (FUN_100356F0,
         * ?DirtyRect@ClusterMap@HaStar@gpg@@QAEXABV?$Rect2@H@3@@Z_0)
         *
         * What it does:
         * Marks clustered occupancy caches dirty for the supplied world rect.
         */
        void DirtyRect(const gpg::Rect2i& worldRect);

        /**
         * Address: 0x008E3C00 (FUN_008E3C00,
         * ?BackgroundWork@ClusterMap@HaStar@gpg@@QAEXAAH@Z)
         *
         * What it does:
         * Advances background cluster rebuild work using the caller-provided budget.
         */
        void BackgroundWork(int& budget);

        /**
         * Address: 0x008E37D0 (FUN_008E37D0,
         * ?WorkOnCluster@ClusterMap@HaStar@gpg@@QAE_NHHHAAH@Z)
         *
         * What it does:
         * Rebuilds one cluster node and updates check/progress bits.
         */
        [[nodiscard]] bool WorkOnCluster(int width, int height, int level, int& budget);

        /**
         * Address: 0x008E3BC0 (FUN_008E3BC0,
         * ?EnsureClusterExists@ClusterMap@HaStar@gpg@@QAEXHHH@Z)
         *
         * What it does:
         * Forces the requested cluster to be available by repeatedly running background work.
         */
        void EnsureClusterExists(int width, unsigned int height, int level);

    public:
        std::uint32_t mNumLevels;
        std::int32_t mWidth;
        std::int32_t mHeight;
        IOccupationSource* mSrc;
        ClusterCache mCache;
        Subcluster mLevels[4];
        gpg::BitArray2D mCheckLevels[4];
        std::uint8_t mIsDone;
        std::uint8_t pad_89[3];
        std::uint32_t mProgress;
        gpg::Rect2i mArea;
    };

    static_assert(sizeof(OccupationData) == 0x14, "OccupationData size must be 0x14");
    static_assert(sizeof(ICache) == 0x04, "ICache size must be 0x04");
    static_assert(sizeof(Cluster) == 0x04, "Cluster size must be 0x04");
    static_assert(sizeof(SubclusterData) == 0x44, "SubclusterData size must be 0x44");
    static_assert(sizeof(Subcluster) == 0x0C, "Subcluster size must be 0x0C");
    static_assert(sizeof(IOccupationSource) == 0x04, "IOccupationSource size must be 0x04");
    static_assert(sizeof(ClusterCache) == 0x08, "ClusterCache size must be 0x08");
    static_assert(sizeof(ClusterMap) == 0xA0, "ClusterMap size must be 0xA0");

    static_assert(offsetof(ClusterMap, mCache) == 0x10, "ClusterMap::mCache offset must be 0x10");
    static_assert(offsetof(ClusterMap, mLevels) == 0x18, "ClusterMap::mLevels offset must be 0x18");
    static_assert(offsetof(ClusterMap, mCheckLevels) == 0x48, "ClusterMap::mCheckLevels offset must be 0x48");
    static_assert(offsetof(ClusterMap, mIsDone) == 0x88, "ClusterMap::mIsDone offset must be 0x88");
    static_assert(offsetof(ClusterMap, mProgress) == 0x8C, "ClusterMap::mProgress offset must be 0x8C");
    static_assert(offsetof(ClusterMap, mArea) == 0x90, "ClusterMap::mArea offset must be 0x90");
}
