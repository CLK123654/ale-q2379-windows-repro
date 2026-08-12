
\copy auth.tenant (tenant_id, display_name, meter_prefix) FROM '__TENANT_CSV__' WITH (FORMAT csv, HEADER true)

\copy auth.actor_tenant_grant (actor_name, tenant_id, can_read, can_write, can_report) FROM '__ACTOR_GRANT_CSV__' WITH (FORMAT csv, HEADER true)

\copy core.meter_interval (interval_id, tenant_id, meter_id, observed_at, kwh, quality_flag, billing_state, internal_note, revision) FROM '__METER_INTERVAL_CSV__' WITH (FORMAT csv, HEADER true)
