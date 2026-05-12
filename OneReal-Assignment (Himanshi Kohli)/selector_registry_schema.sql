-- ============================================================================
-- AGENT VERIFICATION SYSTEM — SELECTOR REGISTRY SCHEMA
--
-- Holds versioned, hot-updatable selector strategies for every (site, flow,
-- element) tuple. Workers read the highest-version active row at runtime.
-- Edits happen via NocoDB (or any tool); audit_log writes are enforced by a
-- Postgres trigger so the audit invariant cannot be bypassed.
--
-- Designed for: Postgres 15+
-- ============================================================================


-- ============================================================================
-- TABLE: selector_registry

-- Example Insert query for DRE - License Lookup input: 

-- INSERT INTO selector_registry
--     (target, flow, step, strategies, version, source, created_by, jira_ref, notes)
-- VALUES (
--     'dre.ca',
--     'license_lookup',
--     'license_input',
--   '[
--    {"kind":"css","value":"#LicenseNumber"},
--    {"kind":"css","value":"input[name=LicenseNumber]"},
--    {"kind":"role","role":"textbox","name":"License Number"}
--  ]'::jsonb,
--  1, true, 'human', 'ops');


-- ============================================================================

CREATE TABLE selector_registry (
    -- Surrogate primary key
    id              BIGSERIAL    PRIMARY KEY,

    -- Composite identity: which element on which website's which workflow
    target          TEXT         NOT NULL,   -- 'joinreal' | 'dre.ca' | 'dre.tx' | ...
    flow            TEXT         NOT NULL,   -- 'search_by_name' | 'license_lookup' | ...
    step            TEXT         NOT NULL,   -- 'name_input' | 'submit_button' | ...

    -- The actual locator ladder (ordered array of strategies).
    -- Example payload:
    -- [
    --   {"kind": "testid", "value": "agent-search-name"},
    --   {"kind": "role",   "role": "textbox", "name": "Find Agent by Name"},
    --   {"kind": "text",   "value": "Find Agent by Name"},
    --   {"kind": "css",    "value": "input[placeholder*='agent' i]"}
    -- ]
    strategies      JSONB        NOT NULL,

    -- Versioning + activation
    version         INT          NOT NULL DEFAULT 1,
    active          BOOLEAN      NOT NULL DEFAULT TRUE,

    -- Provenance and approval (supports Phase 2 AI flow)
    source          TEXT         NOT NULL DEFAULT 'human',
                                    -- 'human' | 'ai-self-heal' | 'migration'
    created_by      TEXT         NOT NULL,        -- username or service identity
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    approved_by     TEXT,                         -- NULL until human approves
    approved_at     TIMESTAMPTZ,

    -- Cross-references and operator notes
    jira_ref        TEXT,                         -- e.g., 'REAL-1234'
    notes           TEXT,

    -- A version is uniquely identified by (target, flow, step, version)
    CONSTRAINT uniq_selector_version
        UNIQUE (target, flow, step, version),

    -- The strategies column must be a non-empty JSON array
    CONSTRAINT strategies_is_array
        CHECK (jsonb_typeof(strategies) = 'array'),
    CONSTRAINT strategies_not_empty
        CHECK (jsonb_array_length(strategies) >= 1),

    -- AI-sourced rows must have an approver before they can go active
    CONSTRAINT ai_rows_must_be_approved_to_be_active
        CHECK (
            source <> 'ai-self-heal'
            OR active = FALSE
            OR approved_by IS NOT NULL
        )
);

-- Hot path: the worker query.
-- Workers run:
--   SELECT strategies FROM selector_registry
--   WHERE target=$1 AND flow=$2 AND step=$3 AND active = TRUE
--   ORDER BY version DESC LIMIT 1;
-- This index makes that O(1) regardless of history depth.
CREATE INDEX idx_selector_active_lookup
    ON selector_registry (target, flow, step, version DESC)
    WHERE active = TRUE;

-- For history queries ("show me everything that's ever been changed for X")
CREATE INDEX idx_selector_history
    ON selector_registry (target, flow, step, created_at DESC);

-- For audit reports filtered by Jira ticket
CREATE INDEX idx_selector_jira
    ON selector_registry (jira_ref)
    WHERE jira_ref IS NOT NULL;


-- ============================================================================
-- TABLE: audit_log
-- Append-only history. Receives a row from the trigger below for every
-- change to selector_registry, regardless of which tool issued the change.
-- ============================================================================

CREATE TABLE audit_log (
    id              BIGSERIAL    PRIMARY KEY,
    occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    actor           TEXT         NOT NULL,    -- Postgres user / service identity
    action          TEXT         NOT NULL,    -- 'INSERT' | 'UPDATE' | 'DELETE'
    table_name      TEXT         NOT NULL,    -- e.g., 'selector_registry'
    row_pk          TEXT         NOT NULL,    -- stringified primary key
    old_value       JSONB,                    -- previous row (NULL on INSERT)
    new_value       JSONB,                    -- new row (NULL on DELETE)
    jira_ref        TEXT
);

CREATE INDEX idx_audit_table_time ON audit_log (table_name, occurred_at DESC);
CREATE INDEX idx_audit_actor      ON audit_log (actor, occurred_at DESC);
CREATE INDEX idx_audit_jira       ON audit_log (jira_ref) WHERE jira_ref IS NOT NULL;


-- ============================================================================
-- TRIGGER: auto-write audit_log on every selector_registry change.
-- This is the load-bearing safety mechanism — nothing gets past it.
-- SECURITY DEFINER lets the trigger insert into audit_log even when the
-- caller (e.g., ops_editor via NocoDB) doesn't have direct INSERT permission.
-- ============================================================================

CREATE OR REPLACE FUNCTION write_selector_audit()
RETURNS TRIGGER
SECURITY DEFINER
AS $$
BEGIN
    INSERT INTO audit_log
        (actor, action, table_name, row_pk, old_value, new_value, jira_ref)
    VALUES (
        current_user,
        TG_OP,
        'selector_registry',
        COALESCE(NEW.id::TEXT, OLD.id::TEXT),
        CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE to_jsonb(OLD) END,
        CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE to_jsonb(NEW) END,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.jira_ref ELSE NEW.jira_ref END
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_selector_registry_audit
AFTER INSERT OR UPDATE OR DELETE ON selector_registry
FOR EACH ROW EXECUTE FUNCTION write_selector_audit();


-- ============================================================================
-- VIEW: active_selectors
-- The current active selector for every (target, flow, step). Workers can
-- read from this view instead of writing the ORDER-BY query themselves;
-- ops can read it in NocoDB to see "what's live right now."
-- ============================================================================

CREATE OR REPLACE VIEW active_selectors AS
SELECT DISTINCT ON (target, flow, step)
    id, target, flow, step, strategies, version,
    source, created_by, created_at, approved_by, approved_at,
    jira_ref, notes
FROM selector_registry
WHERE active = TRUE
ORDER BY target, flow, step, version DESC;


-- ============================================================================
-- ROLES — what NocoDB / workers / AI use to connect.
-- ============================================================================

CREATE ROLE app_worker;       -- the verification workers (read-only)
CREATE ROLE ops_editor;       -- humans editing via NocoDB
CREATE ROLE ops_readonly;     -- viewers
CREATE ROLE ai_proposer;      -- Phase 2 AI; can INSERT but not UPDATE existing

GRANT SELECT ON selector_registry, active_selectors      TO app_worker;
GRANT SELECT, INSERT, UPDATE ON selector_registry        TO ops_editor;
GRANT SELECT ON selector_registry, active_selectors      TO ops_readonly;
GRANT SELECT, INSERT ON selector_registry                TO ai_proposer;
GRANT USAGE, SELECT ON SEQUENCE selector_registry_id_seq TO ops_editor, ai_proposer;

-- audit_log is read-only for everyone — only the trigger writes to it
GRANT SELECT ON audit_log TO app_worker, ops_editor, ops_readonly;


-- ============================================================================
-- SAMPLE SEED DATA — JoinReal "Find Agent by Name" input
-- ============================================================================

INSERT INTO selector_registry
    (target, flow, step, strategies, version, source, created_by, jira_ref, notes)
VALUES (
    'joinreal',
    'search_by_name',
    'name_input',
    '[
        {"kind": "testid", "value": "agent-search-name"},
        {"kind": "role",   "role": "textbox", "name": "Find Agent by Name"},
        {"kind": "text",   "value": "Find Agent by Name"},
        {"kind": "css",    "value": "input[placeholder*=''agent'' i]"}
    ]'::jsonb,
    14,
    'human',
    'himanshi.k',
    'REAL-1234',
    'v14 added testid after JR frontend refactor 2026-04-02'
);


-- ============================================================================
-- USAGE EXAMPLES (reference — do not run as part of schema setup)
-- ============================================================================

-- Worker query (reads the live selector for an element):
--
--   SELECT strategies
--   FROM   selector_registry
--   WHERE  target = 'joinreal'
--     AND  flow   = 'search_by_name'
--     AND  step   = 'name_input'
--     AND  active = TRUE
--   ORDER  BY version DESC
--   LIMIT  1;
--
-- Or simply:
--
--   SELECT strategies FROM active_selectors
--   WHERE target='joinreal' AND flow='search_by_name' AND step='name_input';


-- Ops update flow (run as ops_editor in NocoDB or psql):
--
--   BEGIN;
--   UPDATE selector_registry
--   SET    active = FALSE
--   WHERE  target = 'joinreal'
--     AND  flow   = 'search_by_name'
--     AND  step   = 'name_input'
--     AND  active = TRUE;
--
--   INSERT INTO selector_registry
--       (target, flow, step, strategies, version, source, created_by, jira_ref, notes)
--   VALUES (
--       'joinreal', 'search_by_name', 'name_input',
--       '[{"kind":"testid","value":"agent-search-name-v2"}, ...]'::jsonb,
--       15, 'human', 'oncall.engineer', 'REAL-1900',
--       'JR rev 2026-05-08 — testid renamed'
--   );
--   COMMIT;


-- AI proposal flow (Phase 2):
--
--   -- AI inserts a proposal with active=FALSE and approved_by=NULL:
--   INSERT INTO selector_registry
--       (target, flow, step, strategies, version, active,
--        source, created_by, jira_ref, notes)
--   VALUES (
--       'dre.ca', 'license_lookup', 'license_input',
--       '[{"kind":"testid","value":"dre-license-input"}, ...]'::jsonb,
--       6, FALSE, 'ai-self-heal', 'stagehand-bot',
--       'REAL-2113', 'Proposed after locator ladder exhausted on run #abc123'
--   );
--
--   -- Human reviews via Jira, then approves the row in NocoDB:
--   UPDATE selector_registry
--   SET    active      = TRUE,
--          approved_by = 'oncall.engineer',
--          approved_at = now()
--   WHERE  id = <the proposed row's id>;
