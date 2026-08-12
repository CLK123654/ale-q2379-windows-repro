
CREATE ROLE rls_owner NOLOGIN;
CREATE ROLE policy_owner NOLOGIN BYPASSRLS;
CREATE ROLE report_owner NOLOGIN BYPASSRLS;
CREATE ROLE app_reader NOLOGIN;
CREATE ROLE app_writer NOLOGIN;
CREATE ROLE north_reader LOGIN PASSWORD '__ACTOR_PASSWORD__';
CREATE ROLE north_editor LOGIN PASSWORD '__ACTOR_PASSWORD__';
CREATE ROLE south_editor LOGIN PASSWORD '__ACTOR_PASSWORD__';
CREATE ROLE east_reader LOGIN PASSWORD '__ACTOR_PASSWORD__';
CREATE ROLE portfolio_auditor LOGIN PASSWORD '__ACTOR_PASSWORD__';

GRANT app_reader TO north_reader, north_editor, south_editor, east_reader;
GRANT app_writer TO north_editor, south_editor;

CREATE SCHEMA auth AUTHORIZATION rls_owner;
CREATE SCHEMA core AUTHORIZATION rls_owner;
CREATE SCHEMA reporting AUTHORIZATION rls_owner;
