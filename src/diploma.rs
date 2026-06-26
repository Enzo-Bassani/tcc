//! The university diploma credential: claim set and SD-JWT VC issuance.

use std::sync::OnceLock;

use chrono::Utc;
use serde_json::{Value, json};

use crate::db::Student;
use crate::identity::IssuerIdentity;
use crate::sd_jwt;

/// The OID4VCI `credential_configuration_id` for the diploma credential.
pub const CREDENTIAL_CONFIG_ID: &str = "UniversityDiplomaSdJwt";

/// The credential type (`vct`): a stable, non-dereferenceable URN in the MEC namespace.
pub const VCT: &str = "urn:tcc:mec:UniversityDiploma:1";

/// The status list every diploma is registered against.
pub const STATUS_LIST_ID: &str = "diploma-2026";

/// Repo-relative path of the committed Type Metadata artifact (for display / docs).
pub const TYPE_METADATA_PATH: &str = "type-metadata/UniversityDiploma-v1.json";

/// Absolute path to the same artifact, anchored to [`CARGO_MANIFEST_DIR`] so file I/O
/// resolves correctly regardless of the process's working directory.
pub const TYPE_METADATA_ABS: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/type-metadata/UniversityDiploma-v1.json");

/// Selective-disclosure policy for a claim (the SD-JWT VC Type Metadata `sd` field).
#[derive(PartialEq, Eq, Clone, Copy)]
enum Sd {
    /// Selectively disclosable: removed from the signed body, released by the holder.
    Always,
    /// Never disclosable: always present in cleartext in the signed body.
    Never,
}

impl Sd {
    fn as_str(self) -> &'static str {
        match self {
            Sd::Always => "always",
            Sd::Never => "never",
        }
    }
}

/// One claim in the diploma claim set: its JSON path, disclosure policy, whether the issuer
/// must include it (`mandatory`), and bilingual display labels. [`CLAIMS`] is the single
/// source of truth for *both* the selectively-disclosable path set ([`disclosable_paths`] —
/// the `Sd::Always` rows) and the published Type Metadata `claims` array ([`type_metadata`]),
/// so the two can never drift.
struct ClaimDef {
    path: &'static [&'static str],
    sd: Sd,
    /// Issuer must include the claim at issuance. Orthogonal to `sd`: a claim can be both
    /// mandatory (always issued) *and* disclosable (the holder may withhold it at presentation).
    mandatory: bool,
    label_en: &'static str,
    label_pt: &'static str,
}

impl ClaimDef {
    /// Render this claim as a Type Metadata `claims` entry (SD-JWT VC §4.6). `mandatory` is
    /// only emitted when true, to match the spec's "default false / omit" convention.
    fn to_metadata(&self) -> Value {
        let mut entry = json!({
            "path": self.path,
            "sd": self.sd.as_str(),
            "display": [
                { "locale": "en-US", "label": self.label_en },
                { "locale": "pt-BR", "label": self.label_pt },
            ],
        });
        if self.mandatory {
            entry["mandatory"] = json!(true);
        }
        entry
    }
}

/// Terser constructor for a [`ClaimDef`] row (mirrors the metadata column order).
const fn claim(
    path: &'static [&'static str],
    sd: Sd,
    mandatory: bool,
    label_en: &'static str,
    label_pt: &'static str,
) -> ClaimDef {
    ClaimDef { path, sd, mandatory, label_en, label_pt }
}

/// The diploma claim catalog — the single source of truth for the claim set's disclosure
/// policy and display metadata. Row order is preserved in the Type Metadata `claims` array.
/// Everything not marked `Sd::Always` (issuer identity, status, the whole `institution`
/// block) is always present in cleartext; the `degree` and `registry` objects are disclosed
/// per-leaf so the holder can withhold any subset.
static CLAIMS: &[ClaimDef] = &[
    claim(&["student"], Sd::Never, false, "Student", "Estudante"),
    claim(&["student", "full_name"], Sd::Always, true, "Full name", "Nome completo"),
    claim(&["student", "student_id"], Sd::Always, true, "Student ID", "Matrícula"),
    claim(&["student", "date_of_birth"], Sd::Always, true, "Date of birth", "Data de nascimento"),
    claim(&["student", "national_id"], Sd::Always, true, "National ID (CPF)", "CPF"),
    claim(&["student", "nationality"], Sd::Always, false, "Nationality", "Nacionalidade"),
    claim(&["student", "birthplace"], Sd::Always, false, "Place of birth", "Naturalidade"),

    claim(&["institution"], Sd::Never, false, "Institution", "Instituição"),
    claim(&["institution", "name"], Sd::Never, true, "Institution name", "Nome da instituição"),
    claim(&["institution", "acronym"], Sd::Never, false, "Acronym", "Sigla"),
    claim(&["institution", "type"], Sd::Never, false, "Institution type", "Tipo de instituição"),
    claim(&["institution", "emec_code"], Sd::Never, true, "e-MEC code", "Código e-MEC"),
    claim(&["institution", "city"], Sd::Never, false, "City", "Município"),
    claim(&["institution", "state"], Sd::Never, false, "State", "UF"),
    claim(&["institution", "country"], Sd::Never, false, "Country", "País"),
    claim(&["institution", "accreditation_act"], Sd::Never, false, "Accreditation act", "Ato de credenciamento"),

    claim(&["degree"], Sd::Never, false, "Degree", "Grau"),
    claim(&["degree", "title"], Sd::Always, true, "Degree title", "Título conferido"),
    claim(&["degree", "field_of_study"], Sd::Always, true, "Field of study", "Área de formação"),
    claim(&["degree", "level"], Sd::Always, true, "Degree level", "Nível"),
    claim(&["degree", "modality"], Sd::Always, false, "Modality", "Modalidade"),
    claim(&["degree", "workload_hours"], Sd::Always, false, "Workload (hours)", "Carga horária (horas)"),

    claim(&["conclusion_date"], Sd::Always, true, "Course conclusion date", "Data de conclusão do curso"),
    claim(&["graduation_date"], Sd::Always, false, "Graduation date", "Data de colação de grau"),
    claim(&["gpa"], Sd::Always, false, "Grade point average", "Índice de aproveitamento"),

    claim(&["registry"], Sd::Never, false, "Diploma registry", "Registro do diploma"),
    claim(&["registry", "number"], Sd::Always, true, "Registry number", "Número de registro"),
    claim(&["registry", "book"], Sd::Always, false, "Registry book", "Livro"),
    claim(&["registry", "page"], Sd::Always, false, "Registry page", "Folha"),
    claim(&["registry", "registration_date"], Sd::Always, false, "Registration date", "Data de registro"),
    claim(&["registry", "registrar"], Sd::Always, false, "Registrar", "Órgão registrador"),
];

/// The selectively-disclosable claim paths (dotted), derived once from [`CLAIMS`]: exactly
/// the `Sd::Always` rows. Drives `make_selectively_disclosable` in [`issue`]. Cached in a
/// `OnceLock` so issuance doesn't re-walk the catalog per credential.
pub fn disclosable_paths() -> &'static [String] {
    static PATHS: OnceLock<Vec<String>> = OnceLock::new();
    PATHS.get_or_init(|| {
        CLAIMS
            .iter()
            .filter(|c| c.sd == Sd::Always)
            .map(|c| c.path.join("."))
            .collect()
    })
}

/// Build the full (pre-disclosure) claim set for a diploma credential.
#[allow(clippy::too_many_arguments)]
pub fn build_claims(
    student: &Student,
    iss: &str,
    vct: &str,
    jti: &str,
    holder_jwk: &Value,
    status_uri: &str,
    status_index: i32,
) -> Value {
    let now = Utc::now().timestamp();
    let exp = now + 60 * 60 * 24 * 365 * 10; // valid 10 years
    // The diploma is registered with the institution when the degree is conferred
    // (colação de grau); fall back to the course-conclusion date if absent.
    let registration_date = student
        .graduation_date
        .unwrap_or(student.conclusion_date)
        .to_string();
    json!({
        "vct": vct,
        "iss": iss,
        "iat": now,
        "exp": exp,
        "jti": jti,
        "cnf": { "jwk": holder_jwk },
        "status": {
            "status_list": { "idx": status_index, "uri": status_uri }
        },
        "student": {
            "full_name": student.full_name,
            "student_id": student.student_number,
            "date_of_birth": student.date_of_birth.map(|d| d.to_string()),
            "national_id": student.national_id,
            "nationality": student.nationality,
            "birthplace": student.birthplace,
        },
        "institution": {
            "name": "Universidade Federal de Santa Catarina",
            "acronym": "UFSC",
            "type": "Universidade Pública Federal",
            "emec_code": "575",
            "city": "Florianópolis",
            "state": "SC",
            "country": "BR",
            "accreditation_act": "Decreto Federal nº 64.824/1969",
        },
        "degree": {
            "title": student.course_title,
            "field_of_study": student.field_of_study,
            "level": student.degree_level,
            "modality": "Presencial",
            "workload_hours": 3210,
        },
        "conclusion_date": student.conclusion_date.to_string(),
        "graduation_date": student.graduation_date.map(|d| d.to_string()),
        "gpa": student.gpa,
        "registry": {
            "number": student.registry_number,
            "book": student.registry_book,
            "page": student.registry_page,
            "registration_date": registration_date,
            "registrar": "Secretaria de Registro de Diplomas — UFSC",
        },
    })
}

/// Sign a diploma credential as a compact SD-JWT VC (ES256 + `x5c`, injected by
/// the identity).
pub fn issue(identity: &dyn IssuerIdentity, mut claims: Value) -> String {
    let disclosures = sd_jwt::make_selectively_disclosable(&mut claims, disclosable_paths());
    let header = json!({ "alg": "ES256", "typ": "dc+sd-jwt" });
    let issuer_jwt = identity.sign(header, claims);
    sd_jwt::assemble(&issuer_jwt, &disclosures)
}

/// SD-JWT VC Type Metadata document for the diploma `vct`.
///
/// The `vct` is a non-dereferenceable URN ([`VCT`]), so this document is **not** served
/// over HTTP; it ships as the static artifact `type-metadata/UniversityDiploma-v1.json`
/// (regenerate with `cargo run -- type-metadata`). This function is its single source of
/// truth — a test asserts the committed file matches it. The `claims` array is derived from
/// [`CLAIMS`], the same catalog that drives [`disclosable_paths`], so disclosure policy and
/// published metadata can't drift.
pub fn type_metadata(vct: &str) -> Value {
    let claims: Vec<Value> = CLAIMS.iter().map(ClaimDef::to_metadata).collect();
    json!({
        "vct": vct,
        "name": "University Diploma",
        "description": "Academic diploma issued by a higher-education institution as a \
                        course-conclusion credential, following the Brazilian MEC model.",
        "display": [
            {
                "locale": "en-US",
                "name": "University Diploma",
                "description": "Higher-education diploma certifying a conferred degree.",
                "rendering": {
                    "simple": {
                        "logo": {
                            "uri": "https://ufsc.br/assets/brasao-ufsc.png",
                            "alt_text": "Coat of arms of the issuing university"
                        },
                        "background_color": "#0b2a4a",
                        "text_color": "#ffffff"
                    }
                }
            },
            {
                "locale": "pt-BR",
                "name": "Diploma de Graduação",
                "description": "Diploma de ensino superior que certifica o grau conferido.",
                "rendering": {
                    "simple": {
                        "logo": {
                            "uri": "https://ufsc.br/assets/brasao-ufsc.png",
                            "alt_text": "Brasão da universidade emissora"
                        },
                        "background_color": "#0b2a4a",
                        "text_color": "#ffffff"
                    }
                }
            }
        ],
        "claims": claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed Type Metadata artifact must match [`type_metadata`]. If this fails,
    /// regenerate it with `cargo run -- type-metadata` (or `just type-metadata`).
    #[test]
    fn committed_type_metadata_is_in_sync() {
        let committed: Value = serde_json::from_str(
            &std::fs::read_to_string(TYPE_METADATA_ABS).expect("type-metadata artifact is committed"),
        )
        .expect("artifact is valid JSON");
        assert_eq!(
            committed,
            type_metadata(VCT),
            "type-metadata/UniversityDiploma-v1.json is stale — run `just type-metadata`",
        );
    }
}
