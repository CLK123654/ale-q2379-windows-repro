
CREATE TABLE auth.tenant (
  tenant_id text PRIMARY KEY,
  display_name text NOT NULL,
  meter_prefix text NOT NULL
);
ALTER TABLE auth.tenant OWNER TO rls_owner;

CREATE TABLE auth.actor_tenant_grant (
  actor_name text NOT NULL,
  tenant_id text NOT NULL REFERENCES auth.tenant(tenant_id),
  can_read boolean NOT NULL,
  can_write boolean NOT NULL,
  can_report boolean NOT NULL,
  PRIMARY KEY (actor_name, tenant_id)
);
ALTER TABLE auth.actor_tenant_grant OWNER TO rls_owner;

CREATE TABLE core.meter_interval (
  interval_id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES auth.tenant(tenant_id),
  meter_id text NOT NULL,
  observed_at timestamptz NOT NULL,
  kwh numeric(12,3) NOT NULL CHECK (kwh >= 0),
  quality_flag text NOT NULL CHECK (quality_flag IN ('ACTUAL','ESTIMATED')),
  billing_state text NOT NULL CHECK (billing_state IN ('OPEN','SEALED')),
  internal_note text NOT NULL,
  revision integer NOT NULL CHECK (revision > 0),
  UNIQUE (tenant_id, meter_id, observed_at)
);
ALTER TABLE core.meter_interval OWNER TO rls_owner;
CREATE INDEX meter_interval_tenant_time_idx
  ON core.meter_interval (tenant_id, observed_at, interval_id);

GRANT USAGE ON SCHEMA core, reporting TO app_reader, app_writer;
GRANT USAGE ON SCHEMA reporting TO portfolio_auditor;
GRANT USAGE ON SCHEMA auth TO app_reader, app_writer;
GRANT SELECT ON core.meter_interval TO app_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.meter_interval TO app_writer;
