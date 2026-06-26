//! Database access layer. Uses runtime-checked `sqlx` queries so the crate
//! compiles with no database present.

use anyhow::Result;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::status::BitString;

pub async fn connect(url: &str) -> Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await?)
}

pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Students
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct Student {
    pub id: Uuid,
    pub external_sub: String,
    pub student_number: String,
    pub full_name: String,
    pub date_of_birth: Option<NaiveDate>,
    pub national_id: Option<String>,
    pub nationality: Option<String>,
    pub birthplace: Option<String>,
    pub course_title: String,
    pub field_of_study: String,
    pub degree_level: String,
    pub conclusion_date: NaiveDate,
    pub graduation_date: Option<NaiveDate>,
    pub gpa: Option<f64>,
    pub registry_number: Option<String>,
    pub registry_book: Option<String>,
    pub registry_page: Option<String>,
}

impl Student {
    /// An in-memory sample student for the offline `issue-test` CLI.
    pub fn sample() -> Self {
        Self {
            id: Uuid::nil(),
            external_sub: "sample".into(),
            student_number: "2020000000".into(),
            full_name: "Sample Student".into(),
            date_of_birth: NaiveDate::from_ymd_opt(2000, 1, 1),
            national_id: Some("000.000.000-00".into()),
            nationality: Some("Brasileira".into()),
            birthplace: Some("Florianópolis, SC".into()),
            course_title: "Bacharel em Ciência da Computação".into(),
            field_of_study: "Ciência da Computação".into(),
            degree_level: "bachelor".into(),
            conclusion_date: NaiveDate::from_ymd_opt(2026, 5, 15).unwrap(),
            graduation_date: NaiveDate::from_ymd_opt(2026, 8, 28),
            gpa: Some(8.7),
            registry_number: Some("2026.0000".into()),
            registry_book: Some("CC-01".into()),
            registry_page: Some("000".into()),
        }
    }
}

const STUDENT_COLS: &str = "id, external_sub, student_number, full_name, date_of_birth, \
    national_id, nationality, birthplace, course_title, field_of_study, degree_level, \
    conclusion_date, graduation_date, gpa, registry_number, registry_book, registry_page";

/// Upsert the hardcoded demo students. Idempotent and code-authoritative: re-running
/// refreshes the mutable columns from the definitions below (so schema/data changes reach
/// already-seeded rows) while keeping each row's `id` stable for the `issued_credentials` FK.
pub async fn seed_students(pool: &PgPool) -> Result<()> {
    let rows = [
        Student {
            id: Uuid::new_v4(),
            external_sub: "alice".into(),
            student_number: "2020000001".into(),
            full_name: "Alice Turing".into(),
            date_of_birth: NaiveDate::from_ymd_opt(2001, 3, 14),
            national_id: Some("123.456.789-09".into()),
            nationality: Some("Brasileira".into()),
            birthplace: Some("Florianópolis, SC".into()),
            course_title: "Bacharel em Ciência da Computação".into(),
            field_of_study: "Ciência da Computação".into(),
            degree_level: "bachelor".into(),
            conclusion_date: NaiveDate::from_ymd_opt(2026, 5, 15).unwrap(),
            graduation_date: NaiveDate::from_ymd_opt(2026, 8, 28),
            gpa: Some(8.7),
            registry_number: Some("2026.0001".into()),
            registry_book: Some("CC-01".into()),
            registry_page: Some("014".into()),
        },
        Student {
            id: Uuid::new_v4(),
            external_sub: "bob".into(),
            student_number: "2020000002".into(),
            full_name: "Bob Lovelace".into(),
            date_of_birth: NaiveDate::from_ymd_opt(2000, 11, 2),
            national_id: Some("987.654.321-00".into()),
            nationality: Some("Brasileira".into()),
            birthplace: Some("Joinville, SC".into()),
            course_title: "Bacharel em Engenharia de Software".into(),
            field_of_study: "Engenharia de Software".into(),
            degree_level: "bachelor".into(),
            conclusion_date: NaiveDate::from_ymd_opt(2026, 5, 15).unwrap(),
            graduation_date: NaiveDate::from_ymd_opt(2026, 8, 28),
            gpa: Some(9.1),
            registry_number: Some("2026.0002".into()),
            registry_book: Some("ES-01".into()),
            registry_page: Some("007".into()),
        },
    ];
    for s in rows {
        sqlx::query(&format!(
            "INSERT INTO students ({STUDENT_COLS}) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
             ON CONFLICT (external_sub) DO UPDATE SET \
               student_number = EXCLUDED.student_number, \
               full_name = EXCLUDED.full_name, \
               date_of_birth = EXCLUDED.date_of_birth, \
               national_id = EXCLUDED.national_id, \
               nationality = EXCLUDED.nationality, \
               birthplace = EXCLUDED.birthplace, \
               course_title = EXCLUDED.course_title, \
               field_of_study = EXCLUDED.field_of_study, \
               degree_level = EXCLUDED.degree_level, \
               conclusion_date = EXCLUDED.conclusion_date, \
               graduation_date = EXCLUDED.graduation_date, \
               gpa = EXCLUDED.gpa, \
               registry_number = EXCLUDED.registry_number, \
               registry_book = EXCLUDED.registry_book, \
               registry_page = EXCLUDED.registry_page",
        ))
        .bind(s.id)
        .bind(s.external_sub)
        .bind(s.student_number)
        .bind(s.full_name)
        .bind(s.date_of_birth)
        .bind(s.national_id)
        .bind(s.nationality)
        .bind(s.birthplace)
        .bind(s.course_title)
        .bind(s.field_of_study)
        .bind(s.degree_level)
        .bind(s.conclusion_date)
        .bind(s.graduation_date)
        .bind(s.gpa)
        .bind(s.registry_number)
        .bind(s.registry_book)
        .bind(s.registry_page)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn student_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Student>> {
    Ok(
        sqlx::query_as::<_, Student>(&format!("SELECT {STUDENT_COLS} FROM students WHERE id=$1"))
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn student_by_sub(pool: &PgPool, sub: &str) -> Result<Option<Student>> {
    Ok(sqlx::query_as::<_, Student>(&format!(
        "SELECT {STUDENT_COLS} FROM students WHERE external_sub=$1"
    ))
    .bind(sub)
    .fetch_optional(pool)
    .await?)
}

pub async fn student_by_number(pool: &PgPool, number: &str) -> Result<Option<Student>> {
    Ok(sqlx::query_as::<_, Student>(&format!(
        "SELECT {STUDENT_COLS} FROM students WHERE student_number=$1"
    ))
    .bind(number)
    .fetch_optional(pool)
    .await?)
}

// ---------------------------------------------------------------------------
// Issued credentials
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct IssuedCredential {
    pub jti: Uuid,
    pub student_id: Uuid,
    pub vct: String,
    pub status_list_id: String,
    pub status_index: i32,
    pub issued_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_issued_credential(
    pool: &PgPool,
    jti: Uuid,
    student_id: Uuid,
    vct: &str,
    status_list_id: &str,
    status_index: i32,
    claims: &Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO issued_credentials \
         (jti, student_id, vct, status_list_id, status_index, claims_json) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(jti)
    .bind(student_id)
    .bind(vct)
    .bind(status_list_id)
    .bind(status_index)
    .bind(claims)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn issued_credential_by_jti(
    pool: &PgPool,
    jti: Uuid,
) -> Result<Option<IssuedCredential>> {
    Ok(sqlx::query_as::<_, IssuedCredential>(
        "SELECT jti, student_id, vct, status_list_id, status_index, issued_at, revoked_at \
         FROM issued_credentials WHERE jti=$1",
    )
    .bind(jti)
    .fetch_optional(pool)
    .await?)
}

pub async fn mark_revoked(pool: &PgPool, jti: Uuid) -> Result<()> {
    sqlx::query("UPDATE issued_credentials SET revoked_at=now() WHERE jti=$1")
        .bind(jti)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Status lists
// ---------------------------------------------------------------------------

const STATUS_LIST_SIZE_BITS: i32 = 131_072;

/// How many random draws to try before giving up on finding a free index.
/// Occupancy of a 131072-bit list is sparse in practice, so a collision is rare
/// and a few dozen attempts is ample headroom.
const STATUS_INDEX_MAX_ATTEMPTS: u32 = 64;

/// Reserve a free index in `list_id`, creating the list if needed.
///
/// HAIP §6.1 (FMT-6) requires each credential's status-list index to be **unique
/// AND unpredictable**, so rather than a sequential counter we draw a uniformly
/// random index in `[0, size_bits)` and reject any already claimed by an issued
/// credential. The authoritative allocation record is the `issued_credentials`
/// table's `UNIQUE (status_list_id, status_index)` — *not* the status bitstring (a
/// set bit there means *revoked*, not *allocated*). The final UNIQUE constraint at
/// insert time is the ultimate backstop against the (rare) concurrent-pick race.
pub async fn allocate_status_index(pool: &PgPool, list_id: &str, vct: &str) -> Result<i32> {
    use rand::Rng;

    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO status_lists (id, vct, bits, next_index, size_bits) \
         VALUES ($1,$2,$3,0,$4) ON CONFLICT (id) DO NOTHING",
    )
    .bind(list_id)
    .bind(vct)
    .bind(vec![0u8; (STATUS_LIST_SIZE_BITS / 8) as usize])
    .bind(STATUS_LIST_SIZE_BITS)
    .execute(&mut *tx)
    .await?;

    let (size_bits,): (i32,) = sqlx::query_as("SELECT size_bits FROM status_lists WHERE id=$1")
        .bind(list_id)
        .fetch_one(&mut *tx)
        .await?;

    for _ in 0..STATUS_INDEX_MAX_ATTEMPTS {
        let idx: i32 = rand::thread_rng().gen_range(0..size_bits);
        let taken: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM issued_credentials WHERE status_list_id=$1 AND status_index=$2",
        )
        .bind(list_id)
        .bind(idx)
        .fetch_optional(&mut *tx)
        .await?;
        if taken.is_none() {
            tx.commit().await?;
            return Ok(idx);
        }
    }
    Err(anyhow::anyhow!(
        "could not allocate a free status index in '{list_id}' after \
         {STATUS_INDEX_MAX_ATTEMPTS} attempts"
    ))
}

/// Raw bitstring bytes for `list_id`, if it exists.
pub async fn status_list_bits(pool: &PgPool, list_id: &str) -> Result<Option<Vec<u8>>> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT bits FROM status_lists WHERE id=$1")
        .bind(list_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
}

/// Set the bit at `index` in `list_id` to revoked (1).
pub async fn revoke_status_index(pool: &PgPool, list_id: &str, index: i32) -> Result<()> {
    let mut tx = pool.begin().await?;
    let (bits,): (Vec<u8>,) =
        sqlx::query_as("SELECT bits FROM status_lists WHERE id=$1 FOR UPDATE")
            .bind(list_id)
            .fetch_one(&mut *tx)
            .await?;
    let mut bs = BitString::from_bytes(bits);
    bs.set(index as usize, true);
    sqlx::query("UPDATE status_lists SET bits=$1, updated_at=now() WHERE id=$2")
        .bind(bs.into_bytes())
        .bind(list_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OAuth / OID4VCI transient state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct AuthSession {
    pub id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub credential_config_id: String,
    pub state: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_auth_session(
    pool: &PgPool,
    id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    credential_config_id: &str,
    state: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO auth_sessions \
         (id, redirect_uri, code_challenge, code_challenge_method, credential_config_id, state) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(redirect_uri)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(credential_config_id)
    .bind(state)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_auth_session(pool: &PgPool, id: &str) -> Result<Option<AuthSession>> {
    Ok(sqlx::query_as::<_, AuthSession>(
        "SELECT id, redirect_uri, code_challenge, code_challenge_method, \
         credential_config_id, state FROM auth_sessions WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_authorization_code(
    pool: &PgPool,
    code: &str,
    student_id: Uuid,
    redirect_uri: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    credential_config_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO authorization_codes \
         (code, student_id, redirect_uri, code_challenge, code_challenge_method, \
          credential_config_id, expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(code)
    .bind(student_id)
    .bind(redirect_uri)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(credential_config_id)
    .bind(Utc::now() + Duration::minutes(10))
    .execute(pool)
    .await?;
    Ok(())
}

/// Result of consuming an authorization code.
pub struct ConsumedAuthCode {
    pub student_id: Uuid,
    pub code_challenge: String,
    pub credential_config_id: String,
}

/// Atomically consume an authorization code if valid and unexpired.
pub async fn take_authorization_code(
    pool: &PgPool,
    code: &str,
) -> Result<Option<ConsumedAuthCode>> {
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "UPDATE authorization_codes SET consumed=TRUE \
         WHERE code=$1 AND NOT consumed AND expires_at > now() \
         RETURNING student_id, code_challenge, credential_config_id",
    )
    .bind(code)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(student_id, code_challenge, credential_config_id)| ConsumedAuthCode {
        student_id,
        code_challenge,
        credential_config_id,
    }))
}

pub async fn insert_pre_auth_code(
    pool: &PgPool,
    code: &str,
    student_id: Uuid,
    credential_config_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO pre_authorized_codes \
         (code, student_id, credential_config_id, expires_at) VALUES ($1,$2,$3,$4)",
    )
    .bind(code)
    .bind(student_id)
    .bind(credential_config_id)
    .bind(Utc::now() + Duration::hours(24))
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically consume a pre-authorized code, returning `(student_id, config_id)`.
pub async fn take_pre_auth_code(
    pool: &PgPool,
    code: &str,
) -> Result<Option<(Uuid, String)>> {
    Ok(sqlx::query_as(
        "UPDATE pre_authorized_codes SET consumed=TRUE \
         WHERE code=$1 AND NOT consumed AND expires_at > now() \
         RETURNING student_id, credential_config_id",
    )
    .bind(code)
    .fetch_optional(pool)
    .await?)
}

pub async fn insert_access_token(
    pool: &PgPool,
    token: &str,
    student_id: Uuid,
    credential_config_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO access_tokens (token, student_id, credential_config_id, expires_at) \
         VALUES ($1,$2,$3,$4)",
    )
    .bind(token)
    .bind(student_id)
    .bind(credential_config_id)
    .bind(Utc::now() + Duration::hours(1))
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a valid access token, returning `(student_id, credential_config_id)`.
pub async fn get_access_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<(Uuid, String)>> {
    Ok(sqlx::query_as(
        "SELECT student_id, credential_config_id FROM access_tokens \
         WHERE token=$1 AND expires_at > now()",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?)
}

pub async fn insert_nonce(pool: &PgPool, nonce: &str) -> Result<()> {
    sqlx::query("INSERT INTO c_nonces (nonce, expires_at) VALUES ($1,$2)")
        .bind(nonce)
        .bind(Utc::now() + Duration::minutes(5))
        .execute(pool)
        .await?;
    Ok(())
}

/// Consume a c_nonce; returns true if it was valid and unused.
pub async fn consume_nonce(pool: &PgPool, nonce: &str) -> Result<bool> {
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE c_nonces SET consumed=TRUE \
         WHERE nonce=$1 AND NOT consumed AND expires_at > now() RETURNING nonce",
    )
    .bind(nonce)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn insert_credential_offer(pool: &PgPool, id: &str, offer: &Value) -> Result<()> {
    sqlx::query("INSERT INTO credential_offers (id, offer_json, expires_at) VALUES ($1,$2,$3)")
        .bind(id)
        .bind(offer)
        .bind(Utc::now() + Duration::hours(24))
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_credential_offer(pool: &PgPool, id: &str) -> Result<Option<Value>> {
    let row: Option<(Value,)> = sqlx::query_as(
        "SELECT offer_json FROM credential_offers WHERE id=$1 AND expires_at > now()",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}
