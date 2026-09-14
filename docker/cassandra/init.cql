-- ============================================================
-- HMF-Audit Cassandra Schema
-- ============================================================

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
--     bucket_id = page_id / PagesPerBucket
--
-- For the current experiment:
--     PagesPerBucket = 512
--
-- page_data contains the deterministic serialized page contents.
-- page_hash is the authenticated hash h(P) or h(U).

CREATE TABLE IF NOT EXISTS all_pages (
    tree_id         text,
    bucket_id       bigint, -- page_id % 512
    page_id         bigint,

    is_leaf         boolean,

    parent_page_id  bigint,
    next_page_id    bigint,

    page_data       blob,
    page_hash       blob,

    PRIMARY KEY ((tree_id, bucket_id), page_id)
);


-- Stores operational state of the Merkle B+ Tree.
--
-- next_page_id allows PageIDs to remain stable across restarts.

CREATE TABLE IF NOT EXISTS all_tree_state ( --can use with R_L and R_G, Page struct
    tree_id         text PRIMARY KEY,

    root_page_id    bigint,
    root_hash       blob,
    next_page_id    bigint,

    updated_at      timestamp
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

CREATE TABLE IF NOT EXISTS merkle_segment_nodes ( --2^15 records per partition
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
-- 3. UPPER HMF NODES
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
-- Using scope_id avoids nullable fields inside a Cassandra
-- partition key.

CREATE TABLE IF NOT EXISTS upper_merkle_nodes (
    scope_type      text,
    scope_id        text,

    level           int,
    node_index      bigint,

    node_hash       blob,

    PRIMARY KEY (
        (scope_type, scope_id),
        level,
        node_index
    )
)
WITH CLUSTERING ORDER BY (
    level ASC,
    node_index ASC
);


-- ============================================================
-- 4. HMF TREE STATE
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

CREATE TABLE IF NOT EXISTS tree_state_by_id (
    tree_id             text PRIMARY KEY,

    tree_type           text,

    region_id           text,
    shard_id            bigint,

    current_root        blob,

    current_segment_id  bigint,
    leaf_count          bigint,

    updated_at          timestamp
);


-- ============================================================
-- 5. FINALIZED CHECKPOINT HISTORY
-- ============================================================

-- Each checkpoint binds:
--
--     ALL root       = R_L
--     Global HMF root
--
-- checkpoint_id uses timeuuid so checkpoints are naturally
-- sortable by creation order.

CREATE TABLE IF NOT EXISTS checkpoint_roots (
    system_id           text,
    checkpoint_id       timeuuid,

    locator_root        blob,
    global_hmf_root     blob,

    created_at          timestamp,

    PRIMARY KEY ((system_id), checkpoint_id)
)
WITH CLUSTERING ORDER BY (checkpoint_id DESC);


-- ============================================================
-- 6. CURRENT FINALITY POINTER
-- ============================================================

-- Identifies which checkpoint is currently trusted/finalized.
--
-- checkpoint_roots = checkpoint history
-- finality_state   = pointer to the trusted checkpoint

CREATE TABLE IF NOT EXISTS finality_state (
    system_id                   text PRIMARY KEY,

    finalized_checkpoint_id     timeuuid,
    finalized_at                timestamp
)