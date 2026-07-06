-- =====================================================================
-- VulCrawlerDB - PostgreSQL Schema
-- Generated from DBML specification
-- =====================================================================
-- Usage:
--   1. Create the database (if it doesn't exist yet):
--        createdb VulCrawlerDB
--      or, from psql:
--        CREATE DATABASE "VulCrawlerDB";
--   2. Run this script against it:
--        psql -d VulCrawlerDB -f VulCrawlerDB.sql
-- =====================================================================

BEGIN;

-- =====================================================================
-- Auto-managed timestamp triggers
-- created_at is set once via DEFAULT NOW() at insert time (see column defs).
-- updated_at / last_updated are refreshed automatically by these triggers
-- on every UPDATE, so application code should never set them manually.
-- =====================================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION set_last_updated()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- =====================================================================
-- 1. vendor
-- =====================================================================
CREATE TABLE vendor (
    id                      SERIAL PRIMARY KEY,
    name                    VARCHAR NOT NULL,
    country                 VARCHAR,
    security_bulletin_url   VARCHAR,
    created_at              TIMESTAMP DEFAULT NOW(),
    updated_at              TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_vendor_name UNIQUE (name)
);

CREATE TRIGGER trg_vendor_updated_at
BEFORE UPDATE ON vendor
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- 2. android_version
-- =====================================================================
CREATE TABLE android_version (
    id              SERIAL PRIMARY KEY,
    version_name    VARCHAR NOT NULL,
    api_level       INTEGER,
    release_date    DATE,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_android_version_name UNIQUE (version_name)
);

CREATE TRIGGER trg_android_version_updated_at
BEFORE UPDATE ON android_version
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- 3. chipset
-- =====================================================================
CREATE TABLE chipset (
    id              SERIAL PRIMARY KEY,
    vendor          VARCHAR,
    name            VARCHAR NOT NULL,
    model_number    VARCHAR,
    chipset_family  VARCHAR,
    release_date    DATE,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_chipset_name UNIQUE (name)
);

CREATE TRIGGER trg_chipset_updated_at
BEFORE UPDATE ON chipset
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- 4. chipset_component
-- =====================================================================
CREATE TABLE chipset_component (
    id          SERIAL PRIMARY KEY,
    chipset_id  INTEGER REFERENCES chipset(id),
    name        VARCHAR,
    description TEXT,
    CONSTRAINT uq_chipset_component_chipset_name UNIQUE (chipset_id, name)
);

CREATE INDEX idx_chipset_component_chipset_id ON chipset_component(chipset_id);

-- =====================================================================
-- 5. device
-- =====================================================================
CREATE TABLE device (
    id                      SERIAL PRIMARY KEY,
    vendor_id               INTEGER REFERENCES vendor(id),
    chipset_id              INTEGER REFERENCES chipset(id),
    name                    VARCHAR,
    codename                VARCHAR NOT NULL,
    model_number            VARCHAR,
    device_type             VARCHAR,
    launch_os               VARCHAR,
    current_os              VARCHAR,
    launch_user_interface   VARCHAR,
    current_user_interface  VARCHAR,
    source                  VARCHAR,
    region                  VARCHAR,
    launch_date             DATE,
    eol_date                DATE,
    is_flagship             BOOLEAN,
    created_at              TIMESTAMP DEFAULT NOW(),
    updated_at              TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_device_codename UNIQUE (codename)
);

CREATE TRIGGER trg_device_updated_at
BEFORE UPDATE ON device
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_device_vendor_id  ON device(vendor_id);
CREATE INDEX idx_device_chipset_id ON device(chipset_id);

-- =====================================================================
-- 6. device_android_build
-- =====================================================================
CREATE TABLE device_android_build (
    id                      SERIAL PRIMARY KEY,
    device_id               INTEGER REFERENCES device(id),
    android_version_id      INTEGER REFERENCES android_version(id),
    build_number            VARCHAR,
    firmware_version        VARCHAR,
    release_date            DATE,
    security_patch_level    DATE,
    created_at               TIMESTAMP DEFAULT NOW(),
    updated_at               TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_dab_device_build UNIQUE (device_id, build_number)
);

CREATE TRIGGER trg_device_android_build_updated_at
BEFORE UPDATE ON device_android_build
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_dab_device_id          ON device_android_build(device_id);
CREATE INDEX idx_dab_android_version_id ON device_android_build(android_version_id);

-- =====================================================================
-- 7. layer
-- =====================================================================
CREATE TABLE layer (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR NOT NULL UNIQUE,
    description TEXT
);

-- =====================================================================
-- 8. sublayer
-- Composite UNIQUE(layer_id, id) added so component's composite FK
-- below (FOREIGN KEY (layer_id, sublayer_id) REFERENCES sublayer(layer_id, id))
-- has a matching constraint to target -- without this, CREATE TABLE
-- component fails with "there is no unique constraint matching given
-- keys for referenced table sublayer".
-- =====================================================================
CREATE TABLE sublayer (
    id          SERIAL PRIMARY KEY,
    layer_id    INTEGER REFERENCES layer(id),
    name        VARCHAR NOT NULL,
    description TEXT,
    CONSTRAINT uq_sublayer_layer_id_id UNIQUE (layer_id, id)
);

CREATE INDEX idx_sublayer_layer_id ON sublayer(layer_id);

-- =====================================================================
-- 9. preinstalled_app
-- =====================================================================
CREATE TABLE preinstalled_app (
    id              SERIAL PRIMARY KEY,
    device_id       INTEGER REFERENCES device(id),
    layer_id        INTEGER REFERENCES layer(id),
    package_name    VARCHAR,
    version         VARCHAR,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_preinstalled_app_device_package UNIQUE (device_id, package_name)
);

CREATE TRIGGER trg_preinstalled_app_updated_at
BEFORE UPDATE ON preinstalled_app
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_preinstalled_app_device_id ON preinstalled_app(device_id);
CREATE INDEX idx_preinstalled_app_layer_id  ON preinstalled_app(layer_id);

-- =====================================================================
-- 10. cwe
-- =====================================================================
CREATE TABLE cwe (
    cwe_id      INTEGER PRIMARY KEY,
    name        VARCHAR,
    description TEXT
);

-- =====================================================================
-- 11. cve
-- =====================================================================
CREATE TABLE cve (
    id                          VARCHAR PRIMARY KEY,
    description                 TEXT,
    cvss_v2_score               DOUBLE PRECISION,
    cvss_v3_score               DOUBLE PRECISION,
    cvss_v4_score               DOUBLE PRECISION,
    severity                    VARCHAR,
    publish_date                DATE,
    discovery_date              DATE,
    exploited_in_wild           BOOLEAN,
    public_exploit_available    BOOLEAN,
    origin_type                 VARCHAR,
    layer_id                    INTEGER REFERENCES layer(id),
    sublayer_id                 INTEGER REFERENCES sublayer(id),
    created_at                  TIMESTAMP DEFAULT NOW(),
    updated_at                  TIMESTAMP DEFAULT NOW()
);

CREATE TRIGGER trg_cve_updated_at
BEFORE UPDATE ON cve
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_cve_layer_id    ON cve(layer_id);
CREATE INDEX idx_cve_sublayer_id ON cve(sublayer_id);

-- =====================================================================
-- 12. cve_cwe (junction, composite PK)
-- =====================================================================
CREATE TABLE cve_cwe (
    cve_id  VARCHAR REFERENCES cve(id),
    cwe_id  INTEGER REFERENCES cwe(cwe_id),
    PRIMARY KEY (cve_id, cwe_id)
);

-- =====================================================================
-- 13. cpe
-- =====================================================================
CREATE TABLE cpe (
    id          SERIAL PRIMARY KEY,
    cpe_uri     TEXT NOT NULL,
    part        VARCHAR,
    vendor      VARCHAR,
    product     VARCHAR,
    version     VARCHAR,
    CONSTRAINT uq_cpe_cpe_uri UNIQUE (cpe_uri)
);

-- =====================================================================
-- 14. cve_product
-- =====================================================================
CREATE TABLE cve_product (
    id          SERIAL PRIMARY KEY,
    cve_id      VARCHAR REFERENCES cve(id),
    cpe_id      INTEGER REFERENCES cpe(id),
    vulnerable  BOOLEAN
);

CREATE INDEX idx_cve_product_cve_id ON cve_product(cve_id);
CREATE INDEX idx_cve_product_cpe_id ON cve_product(cpe_id);

-- =====================================================================
-- 15. cve_product_version_range
-- =====================================================================
CREATE TABLE cve_product_version_range (
    id                          SERIAL PRIMARY KEY,
    cve_product_id              INTEGER REFERENCES cve_product(id),
    version_start_including     VARCHAR,
    version_start_excluding     VARCHAR,
    version_end_including       VARCHAR,
    version_end_excluding       VARCHAR
);

CREATE INDEX idx_cpvr_cve_product_id ON cve_product_version_range(cve_product_id);

-- =====================================================================
-- 16. cve_reference
-- =====================================================================
CREATE TABLE cve_reference (
    id          SERIAL PRIMARY KEY,
    cve_id      VARCHAR REFERENCES cve(id),
    uri         TEXT,
    source      VARCHAR,
    tags        VARCHAR,
    is_patch    BOOLEAN
);

CREATE INDEX idx_cve_reference_cve_id ON cve_reference(cve_id);

-- =====================================================================
-- 17. cve_risk_metrics
-- =====================================================================
CREATE TABLE cve_risk_metrics (
    id              SERIAL PRIMARY KEY,
    cve_id          VARCHAR REFERENCES cve(id),
    epss_score      DOUBLE PRECISION,
    epss_percentile DOUBLE PRECISION,
    kev_listed      BOOLEAN,
    ransomware_use  BOOLEAN,
    last_updated    TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_cve_risk_metrics_cve_id UNIQUE (cve_id)
);

CREATE TRIGGER trg_cve_risk_metrics_last_updated
BEFORE UPDATE ON cve_risk_metrics
FOR EACH ROW
EXECUTE FUNCTION set_last_updated();

CREATE INDEX idx_cve_risk_metrics_cve_id ON cve_risk_metrics(cve_id);

-- =====================================================================
-- 18. exploit_source
-- =====================================================================
CREATE TABLE exploit_source (
    id      SERIAL PRIMARY KEY,
    name    VARCHAR NOT NULL,
    url     VARCHAR,
    CONSTRAINT uq_exploit_source_name UNIQUE (name)
);

-- =====================================================================
-- 19. cve_exploit
-- =====================================================================
CREATE TABLE cve_exploit (
    id                  SERIAL PRIMARY KEY,
    cve_id              VARCHAR REFERENCES cve(id),
    exploit_source_id   INTEGER REFERENCES exploit_source(id),
    exploit_url         VARCHAR,
    is_weaponized       BOOLEAN,
    first_seen_date     DATE,
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_cve_exploit_cve_url UNIQUE (cve_id, exploit_url)
);

CREATE TRIGGER trg_cve_exploit_updated_at
BEFORE UPDATE ON cve_exploit
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_cve_exploit_cve_id             ON cve_exploit(cve_id);
CREATE INDEX idx_cve_exploit_exploit_source_id  ON cve_exploit(exploit_source_id);

-- =====================================================================
-- 20. cve_timeline_event
-- =====================================================================
CREATE TABLE cve_timeline_event (
    id                  SERIAL PRIMARY KEY,
    cve_id              VARCHAR REFERENCES cve(id),
    event_type          VARCHAR,
    event_date          DATE,
    notes               TEXT,
    source_reference    VARCHAR,
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_cve_timeline_event_type_date UNIQUE (cve_id, event_type, event_date)
);

CREATE TRIGGER trg_cve_timeline_event_updated_at
BEFORE UPDATE ON cve_timeline_event
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_cve_timeline_event_cve_id ON cve_timeline_event(cve_id);

-- =====================================================================
-- 21. source_repository
-- =====================================================================
CREATE TABLE source_repository (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR NOT NULL,
    repo_type   VARCHAR,
    url         VARCHAR,
    branch      VARCHAR,
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_source_repository_name UNIQUE (name)
);

CREATE TRIGGER trg_source_repository_updated_at
BEFORE UPDATE ON source_repository
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- 22. cve_source_mapping
-- =====================================================================
CREATE TABLE cve_source_mapping (
    id                      SERIAL PRIMARY KEY,
    cve_id                  VARCHAR REFERENCES cve(id),
    repository_id           INTEGER REFERENCES source_repository(id),
    vulnerable_commit_hash   VARCHAR,
    patch_commit_hash        VARCHAR,
    vulnerable_file_path     VARCHAR,
    vulnerable_function      VARCHAR,
    vulnerable_variable      VARCHAR,
    diff_patch               TEXT,
    created_at               TIMESTAMP DEFAULT NOW(),
    updated_at               TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_csm_cve_patch_hash UNIQUE (cve_id, patch_commit_hash)
);

CREATE TRIGGER trg_cve_source_mapping_updated_at
BEFORE UPDATE ON cve_source_mapping
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_csm_cve_id        ON cve_source_mapping(cve_id);
CREATE INDEX idx_csm_repository_id ON cve_source_mapping(repository_id);

-- =====================================================================
-- 23. security_bulletin
-- =====================================================================
CREATE TABLE security_bulletin (
    id              SERIAL PRIMARY KEY,
    vendor_id       INTEGER REFERENCES vendor(id),
    title           VARCHAR,
    published_date  DATE,
    severity_level  VARCHAR,
    bulletin_url    VARCHAR,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_security_bulletin_vendor_url UNIQUE (vendor_id, bulletin_url)
);

CREATE TRIGGER trg_security_bulletin_updated_at
BEFORE UPDATE ON security_bulletin
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_security_bulletin_vendor_id ON security_bulletin(vendor_id);

-- =====================================================================
-- 24. vendor_cve
-- =====================================================================
CREATE TABLE vendor_cve (
    id          SERIAL PRIMARY KEY,
    vendor_id   INTEGER REFERENCES vendor(id),
    cve_id      VARCHAR REFERENCES cve(id),
    bulletin_id INTEGER REFERENCES security_bulletin(id),
    patched_date DATE,
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_vendor_cve_vendor_cve_bulletin UNIQUE (vendor_id, cve_id, bulletin_id)
);

CREATE TRIGGER trg_vendor_cve_updated_at
BEFORE UPDATE ON vendor_cve
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_vendor_cve_vendor_id   ON vendor_cve(vendor_id);
CREATE INDEX idx_vendor_cve_cve_id      ON vendor_cve(cve_id);
CREATE INDEX idx_vendor_cve_bulletin_id ON vendor_cve(bulletin_id);

-- =====================================================================
-- 25. cve_affected_device (junction, composite PK)
-- =====================================================================
CREATE TABLE cve_affected_device (
    cve_id      VARCHAR REFERENCES cve(id),
    device_id   INTEGER REFERENCES device(id),
    is_patched  BOOLEAN,
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (cve_id, device_id)
);

CREATE TRIGGER trg_cve_affected_device_updated_at
BEFORE UPDATE ON cve_affected_device
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =====================================================================
-- 26. cve_affected_chipset
-- =====================================================================
CREATE TABLE cve_affected_chipset (
    id          SERIAL PRIMARY KEY,
    cve_id      VARCHAR REFERENCES cve(id),
    chipset_id  INTEGER REFERENCES chipset(id),
    is_patched  BOOLEAN,
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_cve_affected_chipset_cve_chipset UNIQUE (cve_id, chipset_id)
);

CREATE TRIGGER trg_cve_affected_chipset_updated_at
BEFORE UPDATE ON cve_affected_chipset
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_cve_affected_chipset_cve_id     ON cve_affected_chipset(cve_id);
CREATE INDEX idx_cve_affected_chipset_chipset_id ON cve_affected_chipset(chipset_id);

-- =====================================================================
-- 27. cve_affected_component
-- =====================================================================
CREATE TABLE cve_affected_component (
    id              SERIAL PRIMARY KEY,
    cve_id          VARCHAR REFERENCES cve(id),
    component_id    INTEGER REFERENCES chipset_component(id),
    created_at       TIMESTAMP DEFAULT NOW(),
    updated_at       TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_cve_affected_component_cve_component UNIQUE (cve_id, component_id)
);

CREATE TRIGGER trg_cve_affected_component_updated_at
BEFORE UPDATE ON cve_affected_component
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_cve_affected_component_cve_id       ON cve_affected_component(cve_id);
CREATE INDEX idx_cve_affected_component_component_id ON cve_affected_component(component_id);

-- =====================================================================
-- 28. alembic_version
-- =====================================================================
CREATE TABLE alembic_version (
    version_num VARCHAR PRIMARY KEY
);

-- =====================================================================
-- 29. component
-- Composite UNIQUE(id, layer_id, sublayer_id) added so
-- cve_layer_mapping's composite FK below has a matching constraint to
-- target. NOTE: MATCH FULL requires layer_id/sublayer_id to be both
-- NULL or both non-NULL together on the *referencing* side (sublayer_id
-- here is nullable while layer_id is NOT NULL) -- rows with sublayer_id
-- left NULL will be rejected by this FK check. Only safe if every
-- component row always gets a real sublayer_id.
-- =====================================================================
CREATE TABLE component (
    id          SERIAL PRIMARY KEY,
    layer_id    INTEGER NOT NULL,
    sublayer_id INTEGER,
    name        VARCHAR NOT NULL,
    description TEXT,

    FOREIGN KEY (layer_id, sublayer_id) REFERENCES sublayer(layer_id, id) MATCH FULL,
    CONSTRAINT uq_component_id_layer_sublayer UNIQUE (id, layer_id, sublayer_id)
);

-- =====================================================================
-- 30. cve_layer_mapping
-- =====================================================================
CREATE TABLE cve_layer_mapping (
    id           SERIAL PRIMARY KEY,
    cve_id       VARCHAR(20) NOT NULL,
    layer_id     INTEGER NOT NULL,
    sublayer_id  INTEGER,
    component_id INTEGER,

    FOREIGN KEY (component_id, layer_id, sublayer_id)
        REFERENCES component(id, layer_id, sublayer_id)
        MATCH FULL,

    CONSTRAINT unique_cve_architecture_mapping
        UNIQUE (cve_id, layer_id, sublayer_id, component_id)
);

COMMIT;

-- =====================================================================
-- End of VulCrawlerDB schema
-- =====================================================================