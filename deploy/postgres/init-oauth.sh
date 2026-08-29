#!/bin/sh
set -eu

# PostgreSQL accepts only operation-capability roles. The OAuth validator
# verifies that the signed action selects the requested role and builds a v2
# authn_id containing the immutable authority context used by RLS.
oauth_rule='host custody custody_patient_records_reader,custody_schedule_availability_reader,custody_schedule_appointment_creator,custody_org_exporter,custody_patient_importer all oauth issuer=https://tts.custody.internal/database scope=custody.database validator=custody_jwt_validator map=custody_oauth'
temporary_hba="${PGDATA}/pg_hba.conf.custody"

{
  sed -n '/^local /p' "${PGDATA}/pg_hba.conf"
  echo "${oauth_rule}"
  sed -n '/^host/p' "${PGDATA}/pg_hba.conf"
} > "${temporary_hba}"
mv "${temporary_hba}" "${PGDATA}/pg_hba.conf"

authn_pattern='/^v2:[0-9a-f-]+:[A-Za-z_]+:[A-Za-z0-9-]+:[A-Za-z_]+:[0-9a-z]+:[0-9a-z]+:[0-9a-z]+:[0-9a-z]+:[A-Za-z0-9-]+$'
for role in \
  custody_patient_records_reader \
  custody_schedule_availability_reader \
  custody_schedule_appointment_creator \
  custody_org_exporter \
  custody_patient_importer
do
  printf 'custody_oauth %s %s\n' "${authn_pattern}" "${role}" >> "${PGDATA}/pg_ident.conf"
done

psql --set=ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" \
  <<'SQL'
CREATE ROLE custody_data_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE custody_patient_records_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE custody_schedule_availability_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE custody_schedule_appointment_creator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE custody_org_exporter LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE custody_patient_importer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

CREATE SCHEMA custody_context AUTHORIZATION custody_data_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA custody_context FROM PUBLIC;
GRANT USAGE ON SCHEMA public, custody_context TO
  custody_patient_records_reader,
  custody_schedule_availability_reader,
  custody_schedule_appointment_creator,
  custody_org_exporter,
  custody_patient_importer;
GRANT USAGE ON SCHEMA public TO custody_data_owner;

CREATE FUNCTION custody_context.segment(index_number integer) RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE
RETURN pg_catalog.split_part(system_user, ':', index_number);
CREATE FUNCTION custody_context.claim_organization_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE RETURN custody_context.segment(3)::uuid;
CREATE FUNCTION custody_context.claim_principal_kind() RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE RETURN custody_context.segment(4);
CREATE FUNCTION custody_context.claim_subject() RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE RETURN custody_context.segment(5);
CREATE FUNCTION custody_context.claim_access_profile() RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE RETURN custody_context.segment(6);
CREATE FUNCTION custody_context.claim_patient_id() RETURNS integer
LANGUAGE sql STABLE PARALLEL SAFE RETURN NULLIF(custody_context.segment(7), 'none')::integer;
CREATE FUNCTION custody_context.claim_provider_id() RETURNS integer
LANGUAGE sql STABLE PARALLEL SAFE RETURN NULLIF(custody_context.segment(8), 'none')::integer;
CREATE FUNCTION custody_context.claim_resource_provider_id() RETURNS integer
LANGUAGE sql STABLE PARALLEL SAFE RETURN NULLIF(custody_context.segment(9), 'none')::integer;
CREATE FUNCTION custody_context.claim_slot_id() RETURNS integer
LANGUAGE sql STABLE PARALLEL SAFE RETURN NULLIF(custody_context.segment(10), 'none')::integer;
CREATE FUNCTION custody_context.claim_transaction_id() RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE RETURN custody_context.segment(11);

ALTER FUNCTION custody_context.segment(integer) OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_organization_id() OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_principal_kind() OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_subject() OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_access_profile() OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_patient_id() OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_provider_id() OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_resource_provider_id() OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_slot_id() OWNER TO custody_data_owner;
ALTER FUNCTION custody_context.claim_transaction_id() OWNER TO custody_data_owner;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA custody_context FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA custody_context TO
  custody_patient_records_reader,
  custody_schedule_availability_reader,
  custody_schedule_appointment_creator,
  custody_org_exporter,
  custody_patient_importer;

CREATE TABLE patient_records (
  organization_id uuid NOT NULL,
  id integer NOT NULL,
  patient_name text NOT NULL,
  diagnosis text NOT NULL,
  PRIMARY KEY (organization_id, id)
);
CREATE TABLE providers (
  organization_id uuid NOT NULL,
  id integer NOT NULL,
  display_name text NOT NULL,
  PRIMARY KEY (organization_id, id)
);
CREATE TABLE provider_patient_assignments (
  organization_id uuid NOT NULL,
  provider_id integer NOT NULL,
  patient_id integer NOT NULL,
  PRIMARY KEY (organization_id, provider_id, patient_id),
  FOREIGN KEY (organization_id, provider_id) REFERENCES providers (organization_id, id),
  FOREIGN KEY (organization_id, patient_id) REFERENCES patient_records (organization_id, id)
);
CREATE TABLE provider_private_calendar (
  organization_id uuid NOT NULL,
  provider_id integer NOT NULL,
  starts_at timestamptz NOT NULL,
  private_note text NOT NULL,
  PRIMARY KEY (organization_id, provider_id, starts_at)
);
CREATE TABLE provider_bookable_slots (
  organization_id uuid NOT NULL,
  id integer NOT NULL,
  provider_id integer NOT NULL,
  starts_at timestamptz NOT NULL,
  booked boolean NOT NULL DEFAULT false,
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, provider_id, starts_at),
  FOREIGN KEY (organization_id, provider_id) REFERENCES providers (organization_id, id)
);
CREATE TABLE appointments (
  organization_id uuid NOT NULL,
  id bigint GENERATED BY DEFAULT AS IDENTITY,
  patient_id integer NOT NULL,
  provider_id integer NOT NULL,
  slot_id integer NOT NULL,
  status text NOT NULL CHECK (status = 'scheduled'),
  created_by_subject text NOT NULL,
  transaction_id text NOT NULL,
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, slot_id),
  FOREIGN KEY (organization_id, patient_id) REFERENCES patient_records (organization_id, id),
  FOREIGN KEY (organization_id, provider_id) REFERENCES providers (organization_id, id),
  FOREIGN KEY (organization_id, slot_id) REFERENCES provider_bookable_slots (organization_id, id)
);

INSERT INTO patient_records (organization_id, id, patient_name, diagnosis) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 101, 'Ada Lovelace', 'Synthetic follow-up'),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 102, 'Grace Hopper', 'Synthetic review'),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 103, 'Katherine Johnson', 'Synthetic consultation'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 201, 'Alan Turing', 'Synthetic cross-tenant record');
INSERT INTO providers VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, 'Dr. Rivera'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 27, 'Dr. Cross Tenant');
INSERT INTO provider_patient_assignments VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, 101),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, 102);
INSERT INTO provider_private_calendar VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, '2026-08-10 09:00:00+00', 'Existing patient appointment: confidential');
INSERT INTO provider_bookable_slots (organization_id, id, provider_id, starts_at) VALUES
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 812, 17, '2026-08-10 10:00:00+00'),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 813, 17, '2026-08-10 11:00:00+00'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 912, 27, '2026-08-10 10:00:00+00');

ALTER TABLE patient_records OWNER TO custody_data_owner;
ALTER TABLE providers OWNER TO custody_data_owner;
ALTER TABLE provider_patient_assignments OWNER TO custody_data_owner;
ALTER TABLE provider_private_calendar OWNER TO custody_data_owner;
ALTER TABLE provider_bookable_slots OWNER TO custody_data_owner;
ALTER TABLE appointments OWNER TO custody_data_owner;
ALTER SEQUENCE appointments_id_seq OWNER TO custody_data_owner;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
GRANT SELECT ON patient_records TO custody_patient_records_reader, custody_org_exporter;
GRANT SELECT ON provider_patient_assignments TO custody_patient_records_reader;
GRANT SELECT ON provider_bookable_slots TO custody_schedule_availability_reader;

ALTER TABLE patient_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE patient_records FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_patient_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_patient_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_bookable_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_bookable_slots FORCE ROW LEVEL SECURITY;
ALTER TABLE appointments ENABLE ROW LEVEL SECURITY;
ALTER TABLE appointments FORCE ROW LEVEL SECURITY;

CREATE POLICY patient_records_tenant ON patient_records AS RESTRICTIVE FOR SELECT
  TO custody_patient_records_reader, custody_org_exporter
  USING (organization_id = custody_context.claim_organization_id());
CREATE POLICY patient_records_profiles ON patient_records FOR SELECT TO custody_patient_records_reader
  USING (
    custody_context.claim_access_profile() = 'org_scoped'
    OR (custody_context.claim_access_profile() = 'patient_self' AND id = custody_context.claim_patient_id())
    OR (custody_context.claim_access_profile() = 'provider_assigned' AND EXISTS (
      SELECT 1 FROM provider_patient_assignments assignment
      WHERE assignment.organization_id = patient_records.organization_id
        AND assignment.patient_id = patient_records.id
        AND assignment.provider_id = custody_context.claim_provider_id()
    ))
  );
CREATE POLICY patient_records_export ON patient_records FOR SELECT TO custody_org_exporter
  USING (custody_context.claim_access_profile() = 'org_scoped' AND custody_context.claim_principal_kind() = 'external_machine');
CREATE POLICY provider_assignments_context ON provider_patient_assignments FOR SELECT TO custody_patient_records_reader
  USING (organization_id = custody_context.claim_organization_id() AND provider_id = custody_context.claim_provider_id());

CREATE POLICY availability_context ON provider_bookable_slots FOR SELECT TO custody_schedule_availability_reader
  USING (
    organization_id = custody_context.claim_organization_id()
    AND provider_id = custody_context.claim_resource_provider_id()
    AND custody_context.claim_access_profile() = 'patient_self'
    AND NOT booked
  );
CREATE POLICY bookable_slots_owner_context ON provider_bookable_slots FOR ALL TO custody_data_owner
  USING (
    organization_id = custody_context.claim_organization_id()
    AND provider_id = custody_context.claim_resource_provider_id()
    AND id = custody_context.claim_slot_id()
  )
  WITH CHECK (
    organization_id = custody_context.claim_organization_id()
    AND provider_id = custody_context.claim_resource_provider_id()
    AND id = custody_context.claim_slot_id()
  );
CREATE POLICY appointments_owner_context ON appointments FOR ALL TO custody_data_owner
  USING (
    organization_id = custody_context.claim_organization_id()
    AND patient_id = custody_context.claim_patient_id()
    AND provider_id = custody_context.claim_resource_provider_id()
    AND slot_id = custody_context.claim_slot_id()
  )
  WITH CHECK (
    organization_id = custody_context.claim_organization_id()
    AND patient_id = custody_context.claim_patient_id()
    AND provider_id = custody_context.claim_resource_provider_id()
    AND slot_id = custody_context.claim_slot_id()
    AND created_by_subject = custody_context.claim_subject()
    AND transaction_id = custody_context.claim_transaction_id()
  );

-- The function is the only appointment write API. It derives all sensitive
-- columns from signed OAuth context and makes retries idempotent for this demo.
CREATE FUNCTION custody_context.create_appointment()
RETURNS TABLE (appointment_id bigint, patient_id integer, provider_id integer, slot_id integer, status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, custody_context
AS $$
DECLARE
  existing appointments%ROWTYPE;
BEGIN
  IF session_user <> 'custody_schedule_appointment_creator'
     OR custody_context.claim_access_profile() <> 'patient_self' THEN
    RAISE EXCEPTION 'appointment capability denied';
  END IF;

  INSERT INTO appointments (
    organization_id, patient_id, provider_id, slot_id, status, created_by_subject, transaction_id
  )
  SELECT
    custody_context.claim_organization_id(),
    custody_context.claim_patient_id(),
    custody_context.claim_resource_provider_id(),
    custody_context.claim_slot_id(),
    'scheduled',
    custody_context.claim_subject(),
    custody_context.claim_transaction_id()
  FROM provider_bookable_slots slot
  WHERE slot.organization_id = custody_context.claim_organization_id()
    AND slot.id = custody_context.claim_slot_id()
    AND slot.provider_id = custody_context.claim_resource_provider_id()
  ON CONFLICT ON CONSTRAINT appointments_organization_id_slot_id_key DO NOTHING;

  SELECT * INTO existing
  FROM appointments appointment
  WHERE appointment.organization_id = custody_context.claim_organization_id()
    AND appointment.slot_id = custody_context.claim_slot_id()
    AND appointment.patient_id = custody_context.claim_patient_id()
    AND appointment.provider_id = custody_context.claim_resource_provider_id();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'slot is unavailable';
  END IF;
  UPDATE provider_bookable_slots slot
  SET booked = true
  WHERE slot.organization_id = existing.organization_id
    AND slot.id = existing.slot_id;
  RETURN QUERY SELECT existing.id, existing.patient_id, existing.provider_id, existing.slot_id, existing.status;
END
$$;
ALTER FUNCTION custody_context.create_appointment() OWNER TO custody_data_owner;
REVOKE ALL ON FUNCTION custody_context.create_appointment() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION custody_context.create_appointment() TO custody_schedule_appointment_creator;
SQL
