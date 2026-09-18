-- ============================================================
-- HMF-Audit Cassandra Schema
-- ============================================================
-- Bootstrap schema for a fresh keyspace. CREATE TABLE IF NOT EXISTS does
-- not add columns to existing tables; existing installations need an
-- explicit ALTER TABLE migration and backfill before using new fields.
--
-- Storage contract (enforced by the application):
-- * All Merkle hashes and state_commitment values are 32-byte SHA-256 blobs.
-- * region_id is text; shard_id, segment_id, page_id and node_index are
--   nonnegative signed 64-bit integers. Convert Go string/uint64 IDs with
--   validation at the storage boundary; never silently truncate them.
-- * level = 0 denotes leaves; node_index is zero-based within that level.
-- * Tree/scope IDs use one canonical, unambiguous encoding everywhere.
--   The human-readable examples below require escaping reserved delimiters.
-- * Mutable pages/nodes describe the latest committed state only. The
--   writer must coordinate updates and checkpoint publication with readers
--   so an audit never consumes a mixture of states. These tables alone do
--   not implement that protocol or retain historical proof snapshots.
-- * The blockchain remains the authority for finalized checkpoint roots.
--
-- This schema retains whole-page ALL blobs and the existing table names;
-- README section 7's slot-row layout and six-table list need synchronization.

CREATE KEYSPACE IF NOT EXISTS hmf_audit
WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'datacenter1': 1
};

USE hmf_audit;

-- ============================================================
-- 1. AUTHENTICATED LOG LOCATOR (ALL)
-- ============================================================

-- Stores Merkle B+ Tree pages.
--
-- bucket_id is derived from PageID:
--
--     bucket_id = floor(page_id / pages_per_bucket)
--
-- For the current experiment:
--     pages_per_bucket = 512 (persisted in all_tree_state)
--
-- page_data contains deterministic, versioned serialized page contents:
--   LEAF: ordered (TenantID, ServiceID, LogType, Region, Timestamp, LogID)
--         keys AND their (RID, SID, SegID, LeafID) values.
--   INTERNAL: separator keys, ordered child page IDs and child hashes.
-- Serialize references as IDs, not Go pointers. Preserve the full logical
-- timestamp precision in the blob (CQL timestamp metadata is milliseconds).
-- Leaf hashes bind PageID, NextPageID, keys, and physical addresses. This
-- authenticates both each mapping and the linked-leaf order used by range
-- proofs. Hashing only keys would leave both properties unauthenticated.
-- page_hash is the authenticated hash h(P) or h(U).
-- parent_page_id is NULL for the root; next_page_id is NULL for internal
-- pages and the last leaf. Redundant columns must agree with page_data.

CREATE TABLE IF NOT EXISTS all_pages (
    tree_id         text,
    bucket_id       bigint,
    page_id         bigint,

    is_leaf         boolean,

    parent_page_id  bigint,
    next_page_id    bigint,

    page_data       blob,
    format_version  int,
    page_hash       blob,

    PRIMARY KEY ((tree_id, bucket_id), page_id)
);


-- Stores operational state of the Merkle B+ Tree.
--
-- next_page_id allows PageIDs to remain stable across restarts.
-- root_hash is R_L. tree_id identifies the ALL, not an HMF tree.
-- tree_height counts edges from root to leaf (a leaf root has height 0).
-- record_count counts locator entries; page_count counts live pages.
-- tree_order is the maximum number of children per internal page.
-- pages_per_bucket is fixed for the lifetime of the persisted page layout.

CREATE TABLE IF NOT EXISTS all_tree_state (
    tree_id          text PRIMARY KEY,

    root_page_id     bigint,
    root_hash        blob,
    next_page_id     bigint,
    tree_height      int,
    tree_order       int,
    record_count     bigint,
    page_count       bigint,
    pages_per_bucket int,

    updated_at       timestamp
);


-- ============================================================
-- 2. LOCAL SEGMENT MERKLE TREES
-- ============================================================

-- A Local Segment is a bounded Merkle tree.
--
-- One Cassandra partition corresponds to one physical segment:
--
--     (region_id, shard_id, segment_id)
--
-- level + node_index identify a Merkle node within that segment.
-- With B = 2^14 leaves, a full binary tree stores 2^15 - 1 nodes.
-- An unpaired node is promoted unchanged, as specified in the README.
-- Sealed segment nodes are immutable and remain part of the current HMF.

CREATE TABLE IF NOT EXISTS merkle_segment_nodes ( -- each segment = 1 parition
    region_id       text,
    shard_id        bigint,
    segment_id      bigint,

    level           int,
    node_index      bigint,

    node_hash       blob,

    PRIMARY KEY (
        (region_id, shard_id, segment_id),
        level,
        node_index
    )
)
WITH CLUSTERING ORDER BY (
    level ASC,
    node_index ASC
);


-- ============================================================
-- 3. SEGMENT METADATA BY SHARD
-- ============================================================

-- Enumerate a shard's segments in numeric segment_id order to rebuild its
-- tree. Only sealed segments contribute leaves to that tree.
-- shard_leaf_index is the zero-based position of a sealed segment's root
-- in the shard tree (NULL while active); do not assume it equals segment_id.
-- Segment IDs must increase within each shard; seal in that order so an
-- existing sealed segment's shard_leaf_index never changes on append.
--
-- start_ts/end_ts are the minimum/maximum log event times, not the segment
-- lifecycle times. created_at controls the maximum active interval Delta.
-- segment_root is provisional while active and immutable after sealing.
-- Sealing freezes the leaf_count, root, event bounds and shard_leaf_index.
-- The SHARD row in tree_state_by_id points to the active segment; do not
-- rely on filtering this table by the non-key sealed column.

CREATE TABLE IF NOT EXISTS hmf_segments_by_shard ( --query segment root by shard
    region_id        text,
    shard_id         bigint,
    segment_id       bigint,

    segment_root     blob,
    leaf_count       bigint,
    shard_leaf_index bigint,
    max_leaves       int, --condition for sealing (leafcount)
    max_age_ms       bigint, --condition for sealing (max time)

    start_ts         timestamp,
    end_ts           timestamp,
    sealed           boolean,
    created_at       timestamp,
    sealed_at        timestamp,

    PRIMARY KEY ((region_id, shard_id), segment_id)
)
WITH CLUSTERING ORDER BY (segment_id ASC);


-- ============================================================
-- 4. SHARD TREE FRONTIERS
-- ============================================================

-- Stores the active append frontier for each shard tree. Load these rows
-- at system start to restore the in-memory ShardTree.Frontiers cache.
-- All shard nodes remain in upper_merkle_nodes for proof generation and
-- tamper localization.

CREATE TABLE IF NOT EXISTS shard_tree_frontiers (
    region_id       text,
    shard_id        bigint,
    level           int,

    node_index      bigint,
    node_hash       blob,

    PRIMARY KEY ((region_id, shard_id), level)
)
WITH CLUSTERING ORDER BY (level ASC);


-- ============================================================
-- 5. UPPER HMF NODES
-- ============================================================

-- Stores authentication nodes above Local Segment level.
--
-- scope_type examples:
--     SHARD
--     REGION
--     GLOBAL
--
-- scope_id examples:
--     "R6:S12"
--     "R6"
--     "GLOBAL"
--
-- bucket_id partitions unbounded shard trees by groups of 2^15 segment-root
-- leaves. For a shard node, derive it from the node's leftmost leaf:
--
--     bucket_id = (node_index * 2^level) / 32768
--
-- REGION and GLOBAL trees use bucket_id = 0.
--
-- Using scope_id avoids nullable fields inside a Cassandra
-- partition key.

CREATE TABLE IF NOT EXISTS upper_merkle_nodes ( --HMFNode
    scope_type      text,
    scope_id        text,
    bucket_id       bigint,

    level           int,
    node_index      bigint,

    node_hash       blob,

    PRIMARY KEY (
        (scope_type, scope_id, bucket_id),
        level,
        node_index
    )
)
WITH CLUSTERING ORDER BY (
    level ASC,
    node_index ASC
);


-- ============================================================
-- 6. HMF TREE STATE
-- ============================================================

-- Stores the currently mutable state of each HMF tree.
--
-- Examples of tree_id:
--     "SEGMENT:R6:S12:500"
--     "SHARD:R6:S12"
--     "REGION:R6"
--     "GLOBAL"
--
-- Some fields may be NULL depending on tree_type.
-- leaf_count counts immediate children: logs for SEGMENT, sealed segments
-- for SHARD, shards for REGION, and regions for GLOBAL. HPP needs this
-- count to handle unpaired-node promotion correctly.
-- tree_height is the highest stored level (a single leaf has height 0).
-- segment_id identifies a SEGMENT row; its lifecycle metadata lives in
-- hmf_segments_by_shard and duplicated roots/counts must agree.
-- current_segment_id and next_segment_id apply only to SHARD rows.
-- current_segment_id is NULL when no segment is active; next_segment_id
-- is the next unused ID and must survive restart.
-- parent_leaf_index maps SHARD/REGION roots into their parent trees;
-- GLOBAL has no parent. SEGMENT positions are in hmf_segments_by_shard.
-- Use a configured region/shard roster ordered by RID/SID to derive these
-- positions before proof-node reads. If that roster changes, rebuild the
-- affected upper trees and position metadata in the same committed state.

CREATE TABLE IF NOT EXISTS tree_state_by_id ( --HMFTreeState
    tree_id             text PRIMARY KEY,

    tree_type           text,

    region_id           text,
    shard_id            bigint,
    segment_id          bigint,

    current_root        blob,

    current_segment_id  bigint,
    next_segment_id     bigint,
    leaf_count          bigint,
    tree_height         int,
    parent_leaf_index   bigint,

    updated_at          timestamp
);


-- ============================================================
-- 7. FINALIZED CHECKPOINT CACHE
-- ============================================================

-- Each checkpoint binds:
--
--     ALL root       = R_L
--     Global HMF root
--
-- Optional local cache of finalized roots; no historical page/node copies.
-- checkpoint_id is a timeuuid for local identity and time ordering;
-- checkpoint_sequence is the coordinated sequence J used in the commitment.
-- Timeuuid order must not be used to infer blockchain finality.
-- state_commitment = H("STATE" || encode(J) || R_L || R_G), with one
-- canonical integer encoding shared by the writer and verifier.
-- blockchain_tx_hash is text to preserve the chain's native representation.

CREATE TABLE IF NOT EXISTS checkpoint_roots ( --historical checkpoint metadata
    system_id               text, --can be dev, production, staging, etc. 
    checkpoint_id           timeuuid,
    checkpoint_sequence     bigint, --basically checkpoint count

    locator_root            blob,
    global_hmf_root          blob,
    state_commitment         blob, --H(checkpoint_seq, R_L, R_G)

    blockchain_tx_hash      text,
    blockchain_block_height bigint,
    anchored_at             timestamp,
    finalized_at            timestamp,

    created_at              timestamp,

    PRIMARY KEY ((system_id), checkpoint_sequence)
)
WITH CLUSTERING ORDER BY (checkpoint_sequence DESC);


-- ============================================================
-- 8. CURRENT FINALIZED CHECKPOINT STATE
-- ============================================================

-- Identifies which checkpoint is currently trusted/finalized.
--
-- checkpoint_roots = optional local checkpoint history cache
-- finality_state   = current checkpoint pointer and complete root/anchor cache
--
-- This is the role called current_checkpoint_state in the README.
-- Duplicated checkpoint fields must match the referenced checkpoint_roots
-- row. Publish only after metadata is durable and the anchor is finalized.
-- Readers must still verify trust against the blockchain. Updating this
-- single row does not make writes across other tables atomic.

CREATE TABLE IF NOT EXISTS finality_state ( --current checkpoint metadata
    system_id                   text PRIMARY KEY,

    finalized_checkpoint_id     timeuuid,
    checkpoint_sequence         bigint,

    locator_tree_id             text,
    locator_root                blob,
    global_hmf_root             blob,
    state_commitment            blob,

    blockchain_tx_hash          text,
    blockchain_block_height     bigint,
    anchored_at                 timestamp,
    finalized_at                timestamp,
    updated_at                  timestamp
);
