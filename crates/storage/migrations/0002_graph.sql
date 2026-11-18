-- The Defensive Graph in Apache AGE.
--
-- The graph has one vertex label, "Node". Each relation name is one edge label.
-- A vertex keeps these properties: id, kind, label, updated_at, props.
-- An edge keeps these properties: props, created_at.

DO $graph$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = 'aegis_graph') THEN
        PERFORM ag_catalog.create_graph('aegis_graph');
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM ag_catalog.ag_label AS l
        JOIN ag_catalog.ag_graph AS g ON g.graphid = l.graph
        WHERE g.name = 'aegis_graph' AND l.name = 'Node'
    ) THEN
        PERFORM ag_catalog.create_vlabel('aegis_graph', 'Node');
    END IF;
END
$graph$;

-- One vertex for each node identifier. The index also serves the lookup by identifier.
CREATE UNIQUE INDEX IF NOT EXISTS node_id_key
    ON aegis_graph."Node" (
        ag_catalog.agtype_access_operator(VARIADIC ARRAY[properties, '"id"'::ag_catalog.agtype])
    );

-- The lookup of nodes by type.
CREATE INDEX IF NOT EXISTS node_kind_idx
    ON aegis_graph."Node" (
        ag_catalog.agtype_access_operator(VARIADIC ARRAY[properties, '"kind"'::ag_catalog.agtype])
    );

-- Makes the edge label for a relation name, with one edge for each pair of nodes.
--
-- The function is safe to call again. It takes a lock, so two sessions cannot make the
-- same label at the same time. The caller must have the CREATE privilege on the graph schema
-- when the label does not exist.
CREATE OR REPLACE FUNCTION aegis.ensure_relation(relation_name text)
RETURNS void
LANGUAGE plpgsql
-- Apache AGE makes a label with names that it does not qualify. Thus `ag_catalog` is necessary here.
SET search_path = pg_catalog, ag_catalog, pg_temp
AS $ensure$
BEGIN
    IF relation_name IS NULL OR relation_name !~ '^[a-z][a-z0-9_]{0,47}$' THEN
        RAISE EXCEPTION 'the relation name is not valid'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_indexes
        WHERE schemaname = 'aegis_graph'
          AND tablename = relation_name
          AND indexname = relation_name || '_start_end_key'
    ) THEN
        RETURN;
    END IF;

    -- The first key is the ASCII text "aegi". The second key selects this operation.
    PERFORM pg_catalog.pg_advisory_xact_lock(1634035561, 2);

    IF NOT EXISTS (
        SELECT 1
        FROM ag_catalog.ag_label AS l
        JOIN ag_catalog.ag_graph AS g ON g.graphid = l.graph
        WHERE g.name = 'aegis_graph' AND l.name = relation_name
    ) THEN
        PERFORM ag_catalog.create_elabel('aegis_graph', relation_name::cstring);
    END IF;

    EXECUTE pg_catalog.format(
        'CREATE UNIQUE INDEX IF NOT EXISTS %I ON aegis_graph.%I (start_id, end_id)',
        relation_name || '_start_end_key',
        relation_name
    );
END
$ensure$;

-- The relation names of the AEGIS contracts. A role with fewer privileges can then use them.
SELECT aegis.ensure_relation(name)
FROM unnest(ARRAY[
    'involves',
    'part_of',
    'acted_on',
    'has_role',
    'owns',
    'authenticated_from',
    'member_of',
    'contained_by'
]) AS name;
