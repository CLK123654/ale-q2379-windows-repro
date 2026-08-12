
CREATE FUNCTION auth.actor_allowed(p_tenant text, p_mode text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, auth, pg_temp
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM auth.actor_tenant_grant AS g
    WHERE g.actor_name = session_user
      AND g.tenant_id = p_tenant
      AND CASE p_mode
            WHEN 'read' THEN g.can_read
            WHEN 'write' THEN g.can_write
            WHEN 'report' THEN g.can_report
            ELSE false
          END
  )
$function$;
ALTER FUNCTION auth.actor_allowed(text, text) OWNER TO policy_owner;
GRANT USAGE ON SCHEMA auth TO policy_owner;
GRANT SELECT ON auth.actor_tenant_grant TO policy_owner;
REVOKE ALL ON FUNCTION auth.actor_allowed(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.actor_allowed(text, text)
  TO app_reader, app_writer, report_owner;

ALTER TABLE core.meter_interval ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.meter_interval FORCE ROW LEVEL SECURITY;

CREATE POLICY meter_select
ON core.meter_interval
FOR SELECT
TO app_reader
USING (auth.actor_allowed(tenant_id, 'read'));

CREATE POLICY meter_insert
ON core.meter_interval
FOR INSERT
TO app_writer
WITH CHECK (auth.actor_allowed(tenant_id, 'write'));

CREATE POLICY meter_update_tenant
ON core.meter_interval
FOR UPDATE
TO app_writer
USING (auth.actor_allowed(tenant_id, 'write'))
WITH CHECK (auth.actor_allowed(tenant_id, 'write'));

CREATE POLICY meter_update_open_only
ON core.meter_interval
AS RESTRICTIVE
FOR UPDATE
TO app_writer
USING (billing_state = 'OPEN')
WITH CHECK (billing_state = 'OPEN');
