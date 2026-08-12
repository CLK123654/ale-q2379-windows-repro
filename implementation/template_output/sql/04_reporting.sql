
CREATE FUNCTION reporting.tenant_daily_summary(p_tenant text)
RETURNS TABLE (
  tenant_id text,
  usage_date date,
  interval_count bigint,
  total_kwh numeric,
  estimated_count bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, auth, core, pg_temp
AS $function$
BEGIN
  IF NOT auth.actor_allowed(p_tenant, 'report') THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = 'RPT001: caller is not authorized for requested tenant';
  END IF;
  RETURN QUERY
  SELECT
    m.tenant_id,
    (m.observed_at AT TIME ZONE 'UTC')::date AS usage_date,
    count(*)::bigint,
    sum(m.kwh)::numeric,
    count(*) FILTER (WHERE m.quality_flag = 'ESTIMATED')::bigint
  FROM core.meter_interval AS m
  WHERE m.tenant_id = p_tenant
  GROUP BY m.tenant_id, (m.observed_at AT TIME ZONE 'UTC')::date
  ORDER BY usage_date;
END
$function$;
ALTER FUNCTION reporting.tenant_daily_summary(text) OWNER TO report_owner;
GRANT USAGE ON SCHEMA core, auth TO report_owner;
GRANT SELECT ON core.meter_interval TO report_owner;
REVOKE ALL ON FUNCTION reporting.tenant_daily_summary(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reporting.tenant_daily_summary(text)
  TO app_reader, app_writer, portfolio_auditor;
