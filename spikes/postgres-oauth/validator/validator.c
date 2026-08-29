/*
 * Custody PostgreSQL 18 OAuth validator.
 *
 * The module validates a narrowly profiled Ed25519 JWT offline. The TTS
 * atomically publishes its raw database public key before PostgreSQL starts.
 * No network call occurs inside a PostgreSQL backend.
 */
#include "postgres.h"

#include "fmgr.h"
#include "libpq/oauth.h"

#include <ctype.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <time.h>

PG_MODULE_MAGIC;

#define DATABASE_ISSUER "https://tts.custody.internal/database"
#define DATABASE_AUDIENCE "postgresql://custody"
#define DATABASE_TYPE "at+jwt"
#define DATABASE_KEY_ID "db-current"
#define ROLE_RECORDS_READER "custody_patient_records_reader"
#define ROLE_AVAILABILITY_READER "custody_schedule_availability_reader"
#define ROLE_APPOINTMENT_CREATOR "custody_schedule_appointment_creator"
#define ROLE_ORG_EXPORTER "custody_org_exporter"
#define ROLE_PATIENT_IMPORTER "custody_patient_importer"
#define PUBLIC_KEY_PATH "/var/lib/postgresql/jwks/db-current.pub"
#define MAX_TOKEN_SIZE 16384
#define MAX_JSON_SIZE 8192
#define CLOCK_SKEW_SECONDS 5
#define MAX_TOKEN_LIFETIME_SECONDS 30

static bool validate_token(const ValidatorModuleState *state,
                           const char *token,
                           const char *role,
                           ValidatorModuleResult *result);
typedef struct TokenContext
{
    char *txn;
    char *jti;
    char *subject;
    char *organization_id;
    char *principal_kind;
    char *access_profile;
    char *patient_id;
    char *provider_id;
    char *resource_provider_id;
    char *slot_id;
    char *action;
    char *database_role;
} TokenContext;

static bool verify_database_token(const char *token, TokenContext *context);
static unsigned char *decode_base64url(const char *input, size_t length, size_t *output_length);
static bool claim_equals(json_t *object, const char *name, const char *expected);
static bool audience_contains(json_t *payload, const char *expected);
static bool safe_identifier(const char *value);
static bool safe_uuid(const char *value);
static bool safe_patient_id(const char *value);
static EVP_PKEY *load_public_key(void);
static char *sha256_hex(const char *value);

static const OAuthValidatorCallbacks validator_callbacks = {
    PG_OAUTH_VALIDATOR_MAGIC,
    .validate_cb = validate_token,
};

const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
    return &validator_callbacks;
}

static bool
validate_token(const ValidatorModuleState *state,
               const char *token,
               const char *role,
               ValidatorModuleResult *result)
{
    TokenContext context = {0};
    const char *patient_segment;
    const char *provider_segment;
    const char *resource_provider_segment;
    const char *slot_segment;
    char *authn_id;
    char *jti_hash;

    (void) state;
    result->authorized = false;
    result->authn_id = NULL;

    if (!verify_database_token(token, &context))
        return true;
    if (role == NULL || strcmp(role, context.database_role) != 0)
        return true;

    patient_segment = context.patient_id == NULL ? "none" : context.patient_id;
    provider_segment = context.provider_id == NULL ? "none" : context.provider_id;
    resource_provider_segment = context.resource_provider_id == NULL ? "none" : context.resource_provider_id;
    slot_segment = context.slot_id == NULL ? "none" : context.slot_id;
    authn_id = psprintf("v2:%s:%s:%s:%s:%s:%s:%s:%s:%s",
                       context.organization_id,
                       context.principal_kind,
                       context.subject,
                       context.access_profile,
                       patient_segment,
                       provider_segment,
                       resource_provider_segment,
                       slot_segment,
                       context.txn);
    result->authorized = true;
    result->authn_id = authn_id;
    jti_hash = sha256_hex(context.jti);
    ereport(LOG,
            (errmsg("{\"event\":\"postgres.oauth.accepted\",\"txn\":\"%s\",\"jti_hash\":\"%s\",\"system_user\":\"oauth:%s\",\"mapped_role\":\"%s\",\"org_id\":\"%s\",\"principal_kind\":\"%s\",\"access_profile\":\"%s\",\"subject\":\"%s\",\"action\":\"%s\",\"patient_id\":\"%s\",\"provider_id\":\"%s\"}",
                    context.txn, jti_hash, authn_id, context.database_role,
                    context.organization_id, context.principal_kind,
                    context.access_profile, context.subject, context.action,
                    patient_segment, provider_segment)));
    return true;
}

static bool
verify_database_token(const char *token, TokenContext *context)
{
    const char *first_dot;
    const char *second_dot;
    size_t header_length;
    size_t payload_length;
    size_t signature_length;
    unsigned char *header_bytes = NULL;
    unsigned char *payload_bytes = NULL;
    unsigned char *signature = NULL;
    json_t *header = NULL;
    json_t *payload = NULL;
    json_error_t json_error;
    EVP_PKEY *public_key = NULL;
    EVP_MD_CTX *verify_context = NULL;
    bool valid = false;
    json_t *iat_claim;
    json_t *exp_claim;
    json_t *actor;
    const char *actor_subject;
    const char *txn;
    const char *jti;
    const char *subject;
    const char *organization_id;
    const char *principal_kind;
    const char *access_profile;
    const char *patient_id = NULL;
    const char *provider_id = NULL;
    const char *resource_provider_id = NULL;
    const char *slot_id = NULL;
    const char *action;
    const char *workload;
    const char *database_role;
    const char *expected_role = NULL;
    json_t *patient_claim;
    json_t *provider_claim;
    json_t *resource;
    time_t now;
    json_int_t issued_at;
    json_int_t expires_at;

    if (token == NULL || strlen(token) == 0 || strlen(token) > MAX_TOKEN_SIZE)
        goto cleanup;
    first_dot = strchr(token, '.');
    if (first_dot == NULL)
        goto cleanup;
    second_dot = strchr(first_dot + 1, '.');
    if (second_dot == NULL || strchr(second_dot + 1, '.') != NULL)
        goto cleanup;

    header_bytes = decode_base64url(token, (size_t) (first_dot - token), &header_length);
    payload_bytes = decode_base64url(first_dot + 1,
                                     (size_t) (second_dot - first_dot - 1),
                                     &payload_length);
    signature = decode_base64url(second_dot + 1, strlen(second_dot + 1), &signature_length);
    if (header_bytes == NULL || payload_bytes == NULL || signature == NULL ||
        header_length == 0 || payload_length == 0 ||
        header_length > MAX_JSON_SIZE || payload_length > MAX_JSON_SIZE ||
        signature_length != 64)
        goto cleanup;

    header = json_loadb((const char *) header_bytes, header_length, JSON_REJECT_DUPLICATES, &json_error);
    payload = json_loadb((const char *) payload_bytes, payload_length, JSON_REJECT_DUPLICATES, &json_error);
    if (!json_is_object(header) || !json_is_object(payload))
        goto cleanup;
    if (!claim_equals(header, "alg", "EdDSA") ||
        !claim_equals(header, "typ", DATABASE_TYPE) ||
        !claim_equals(header, "kid", DATABASE_KEY_ID))
        goto cleanup;
    if (!claim_equals(payload, "iss", DATABASE_ISSUER) ||
        !audience_contains(payload, DATABASE_AUDIENCE))
        goto cleanup;

    subject = json_string_value(json_object_get(payload, "sub"));
    organization_id = json_string_value(json_object_get(payload, "org_id"));
    principal_kind = json_string_value(json_object_get(payload, "principal_kind"));
    access_profile = json_string_value(json_object_get(payload, "access_profile"));
    action = json_string_value(json_object_get(payload, "action"));
    workload = json_string_value(json_object_get(payload, "wl"));
    database_role = json_string_value(json_object_get(payload, "db_role"));
    patient_claim = json_object_get(payload, "patient_id");
    provider_claim = json_object_get(payload, "provider_id");
    resource = json_object_get(payload, "resource");
    if (!safe_identifier(subject) || !safe_uuid(organization_id) ||
        principal_kind == NULL || access_profile == NULL || action == NULL ||
        workload == NULL || database_role == NULL || !json_is_object(resource))
        goto cleanup;
    if (strcmp(action, "patient-records.read") == 0)
        expected_role = ROLE_RECORDS_READER;
    else if (strcmp(action, "schedule.availability.read") == 0)
        expected_role = ROLE_AVAILABILITY_READER;
    else if (strcmp(action, "schedule.appointment.create") == 0)
        expected_role = ROLE_APPOINTMENT_CREATOR;
    else if (strcmp(action, "patient-records.export") == 0)
        expected_role = ROLE_ORG_EXPORTER;
    else if (strcmp(action, "patient-records.import") == 0)
        expected_role = ROLE_PATIENT_IMPORTER;
    else
        goto cleanup;
    if (strcmp(database_role, expected_role) != 0)
        goto cleanup;
    if (strcmp(principal_kind, "human") != 0 &&
        strcmp(principal_kind, "autonomous_agent") != 0 &&
        strcmp(principal_kind, "external_machine") != 0)
        goto cleanup;
    if (strcmp(access_profile, "patient_self") == 0) {
        patient_id = json_string_value(patient_claim);
        if (!safe_patient_id(patient_id))
            goto cleanup;
    }
    else if (strcmp(access_profile, "provider_assigned") == 0) {
        provider_id = json_string_value(provider_claim);
        if (!safe_patient_id(provider_id) || patient_claim != NULL)
            goto cleanup;
    }
    else if (strcmp(access_profile, "org_scoped") == 0) {
        if (patient_claim != NULL || provider_claim != NULL)
            goto cleanup;
    }
    else
        goto cleanup;
    resource_provider_id = json_string_value(json_object_get(resource, "provider_id"));
    slot_id = json_string_value(json_object_get(resource, "slot_id"));
    if ((resource_provider_id != NULL && !safe_patient_id(resource_provider_id)) ||
        (slot_id != NULL && !safe_patient_id(slot_id)))
        goto cleanup;

    iat_claim = json_object_get(payload, "iat");
    exp_claim = json_object_get(payload, "exp");
    if (!json_is_integer(iat_claim) || !json_is_integer(exp_claim))
        goto cleanup;
    issued_at = json_integer_value(iat_claim);
    expires_at = json_integer_value(exp_claim);
    now = time(NULL);
    if (issued_at > (json_int_t) now + CLOCK_SKEW_SECONDS ||
        expires_at < (json_int_t) now - CLOCK_SKEW_SECONDS ||
        expires_at <= issued_at ||
        expires_at - issued_at > MAX_TOKEN_LIFETIME_SECONDS)
        goto cleanup;

    actor = json_object_get(payload, "act");
    if (actor != NULL) {
        if (!json_is_object(actor))
            goto cleanup;
        actor_subject = json_string_value(json_object_get(actor, "sub"));
        if (actor_subject == NULL || strcmp(actor_subject, "agent-42") != 0)
            goto cleanup;
    }
    if (strcmp(workload, "agent-42") != 0 && strcmp(workload, "demo-app") != 0 &&
        strcmp(workload, "automation-principal") != 0 && strcmp(workload, "external-exporter") != 0)
        goto cleanup;
    txn = json_string_value(json_object_get(payload, "txn"));
    jti = json_string_value(json_object_get(payload, "jti"));
    if (!safe_identifier(txn) || !safe_identifier(jti))
        goto cleanup;

    public_key = load_public_key();
    if (public_key == NULL)
        goto cleanup;
    verify_context = EVP_MD_CTX_new();
    if (verify_context == NULL ||
        EVP_DigestVerifyInit(verify_context, NULL, NULL, NULL, public_key) != 1 ||
        EVP_DigestVerify(verify_context,
                         signature,
                         signature_length,
                         (const unsigned char *) token,
                         (size_t) (second_dot - token)) != 1)
        goto cleanup;

    context->txn = pstrdup(txn);
    context->jti = pstrdup(jti);
    context->subject = pstrdup(subject);
    context->organization_id = pstrdup(organization_id);
    context->principal_kind = pstrdup(principal_kind);
    context->access_profile = pstrdup(access_profile);
    context->patient_id = patient_id == NULL ? NULL : pstrdup(patient_id);
    context->provider_id = provider_id == NULL ? NULL : pstrdup(provider_id);
    context->resource_provider_id = resource_provider_id == NULL ? NULL : pstrdup(resource_provider_id);
    context->slot_id = slot_id == NULL ? NULL : pstrdup(slot_id);
    context->action = pstrdup(action);
    context->database_role = pstrdup(database_role);
    valid = true;

cleanup:
    if (verify_context != NULL)
        EVP_MD_CTX_free(verify_context);
    if (public_key != NULL)
        EVP_PKEY_free(public_key);
    if (header != NULL)
        json_decref(header);
    if (payload != NULL)
        json_decref(payload);
    if (header_bytes != NULL)
        pfree(header_bytes);
    if (payload_bytes != NULL)
        pfree(payload_bytes);
    if (signature != NULL)
        pfree(signature);
    return valid;
}

static unsigned char *
decode_base64url(const char *input, size_t length, size_t *output_length)
{
    size_t padded_length;
    size_t padding;
    char *padded;
    unsigned char *output;
    int decoded_length;
    size_t index;

    if (input == NULL || length == 0 || length > MAX_TOKEN_SIZE || length % 4 == 1)
        return NULL;
    padded_length = ((length + 3) / 4) * 4;
    padding = padded_length - length;
    padded = palloc(padded_length + 1);
    for (index = 0; index < length; index++) {
        if (input[index] == '-')
            padded[index] = '+';
        else if (input[index] == '_')
            padded[index] = '/';
        else if (isalnum((unsigned char) input[index]))
            padded[index] = input[index];
        else {
            pfree(padded);
            return NULL;
        }
    }
    while (index < padded_length)
        padded[index++] = '=';
    padded[padded_length] = '\0';
    output = palloc((padded_length / 4) * 3 + 1);
    decoded_length = EVP_DecodeBlock(output, (const unsigned char *) padded, (int) padded_length);
    pfree(padded);
    if (decoded_length < 0 || (size_t) decoded_length < padding) {
        pfree(output);
        return NULL;
    }
    *output_length = (size_t) decoded_length - padding;
    output[*output_length] = '\0';
    return output;
}

static bool
claim_equals(json_t *object, const char *name, const char *expected)
{
    const char *value = json_string_value(json_object_get(object, name));
    return value != NULL && strcmp(value, expected) == 0;
}

static bool
audience_contains(json_t *payload, const char *expected)
{
    json_t *audience = json_object_get(payload, "aud");
    size_t index;
    json_t *value;

    if (json_is_string(audience))
        return strcmp(json_string_value(audience), expected) == 0;
    if (!json_is_array(audience))
        return false;
    json_array_foreach(audience, index, value) {
        if (json_is_string(value) && strcmp(json_string_value(value), expected) == 0)
            return true;
    }
    return false;
}

static bool
safe_identifier(const char *value)
{
    size_t length;
    size_t index;

    if (value == NULL)
        return false;
    length = strlen(value);
    if (length == 0 || length > 128)
        return false;
    for (index = 0; index < length; index++) {
        if (!isalnum((unsigned char) value[index]) && value[index] != '-')
            return false;
    }
    return true;
}

static bool
safe_uuid(const char *value)
{
    size_t index;

    if (value == NULL || strlen(value) != 36)
        return false;
    for (index = 0; index < 36; index++) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value[index] != '-')
                return false;
        }
        else if (!isdigit((unsigned char) value[index]) &&
                 (value[index] < 'a' || value[index] > 'f'))
            return false;
    }
    return value[14] >= '1' && value[14] <= '5' &&
           (value[19] == '8' || value[19] == '9' ||
            value[19] == 'a' || value[19] == 'b');
}

static bool
safe_patient_id(const char *value)
{
    size_t length;
    size_t index;

    if (value == NULL)
        return false;
    length = strlen(value);
    if (length == 0 || length > 19 || value[0] == '0')
        return false;
    for (index = 0; index < length; index++) {
        if (!isdigit((unsigned char) value[index]))
            return false;
    }
    return true;
}

static EVP_PKEY *
load_public_key(void)
{
    struct stat metadata;
    FILE *file;
    char encoded[128];
    size_t length;
    size_t key_length;
    unsigned char *key_bytes;
    EVP_PKEY *key = NULL;
    if (stat(PUBLIC_KEY_PATH, &metadata) != 0 || !S_ISREG(metadata.st_mode))
        return NULL;
    file = fopen(PUBLIC_KEY_PATH, "r");
    if (file == NULL)
        return NULL;
    if (fgets(encoded, sizeof(encoded), file) == NULL || fclose(file) != 0)
        return NULL;
    length = strcspn(encoded, "\r\n");
    key_bytes = decode_base64url(encoded, length, &key_length);
    if (key_bytes != NULL && key_length == 32)
        key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key_bytes, key_length);
    if (key_bytes != NULL)
        pfree(key_bytes);
    return key;
}

static char *
sha256_hex(const char *value)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char *encoded = palloc(SHA256_DIGEST_LENGTH * 2 + 1);
    size_t index;

    SHA256((const unsigned char *) value, strlen(value), digest);
    for (index = 0; index < SHA256_DIGEST_LENGTH; index++)
        snprintf(encoded + (index * 2), 3, "%02x", digest[index]);
    encoded[SHA256_DIGEST_LENGTH * 2] = '\0';
    return encoded;
}
