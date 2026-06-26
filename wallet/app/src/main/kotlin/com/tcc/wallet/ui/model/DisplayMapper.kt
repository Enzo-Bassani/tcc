package com.tcc.wallet.ui.model

import com.tcc.wallet.ssi.SsiEngine
import com.tcc.wallet.ui.theme.BrandGradient
import com.tcc.wallet.ui.theme.DiplomaAccent
import com.tcc.wallet.ui.theme.EnrollAccent
import com.tcc.wallet.ui.theme.Gradient
import com.tcc.wallet.ui.theme.StudentAccent
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Turns a stored compact SD-JWT into a [CredentialView] the UI can render — decoding
 * via [SsiEngine.readCredential] and grouping the decoded claims into sections. The
 * grouping is generic (any credential), with branding (name/monogram/accent) keyed off
 * the `vct` for the known TCC credential types and a sensible fallback otherwise.
 */
object DisplayMapper {

    private data class Branding(val typeName: String, val monogram: String, val accent: Gradient)

    fun from(sdJwt: String, engine: SsiEngine): CredentialView {
        val raw = engine.readCredential(sdJwt)
        val vct = raw.optString("vct")
        val brand = brandingFor(vct)
        return CredentialView(
            id = Integer.toHexString(sdJwt.hashCode()),
            sdJwt = sdJwt,
            vct = vct,
            typeName = brand.typeName,
            issuerName = issuerName(raw),
            holderName = raw.optJSONObject("student")?.optString("full_name").orEmpty(),
            monogram = brand.monogram,
            accent = brand.accent,
            statusLabel = "Valid",
            sections = buildSections(raw),
            rawJson = raw,
        )
    }

    private fun brandingFor(vct: String): Branding = when {
        vct.contains("UniversityDiploma") -> Branding("University Diploma", "UE", DiplomaAccent)
        vct.contains("StudentID") -> Branding("Student ID", "ID", StudentAccent)
        vct.contains("EnrollmentDeclaration") -> Branding("Enrollment Declaration", "ED", EnrollAccent)
        else -> {
            val name = humanizeType(vct)
            Branding(name, monogramOf(name), BrandGradient)
        }
    }

    /** `urn:tcc:mec:UniversityDiploma:1` → "University Diploma". */
    private fun humanizeType(vct: String): String {
        val token = vct.split(':').lastOrNull { it.isNotBlank() && !it.all(Char::isDigit) } ?: vct
        return token.replace(CAMEL_BOUNDARY, " ").ifBlank { "Credential" }
    }

    private fun monogramOf(typeName: String): String {
        val initials = typeName.split(' ').filter { it.isNotBlank() }.map { it.first().uppercaseChar() }
        return (initials.take(2).joinToString("")).ifBlank { "VC" }
    }

    private fun issuerName(raw: JSONObject): String =
        raw.optJSONObject("institution")?.optString("name").takeUnless { it.isNullOrBlank() }
            ?: hostOf(raw.optString("iss"))

    private fun hostOf(uri: String): String =
        HTTP_HOST.find(uri)?.groupValues?.get(1) ?: uri

    // --- sections -------------------------------------------------------------

    private fun buildSections(raw: JSONObject): List<CredentialSection> {
        val out = ArrayList<CredentialSection>()

        objectSection("HOLDER", raw.optJSONObject("student"))?.let(out::add)
        objectSection("DEGREE", raw.optJSONObject("degree"))?.let(out::add)
        objectSection("PROGRAM", raw.optJSONObject("program"))?.let(out::add)
        objectSection("ENROLLMENT", raw.optJSONObject("enrollment"))?.let(out::add)
        objectSection("REGISTRY", raw.optJSONObject("registry"))?.let(out::add)

        issuerSection(raw)?.let(out::add)
        validitySection(raw)?.let(out::add)
        revocationSection(raw)?.let(out::add)
        keyBindingSection(raw)?.let(out::add)

        return out
    }

    /** A section from a flat claim object (scalar leaves only), ordered by [LEAF_ORDER]. */
    private fun objectSection(header: String, obj: JSONObject?): CredentialSection? {
        if (obj == null) return null
        val fields = obj.keys().asSequence()
            .filter { obj.opt(it) !is JSONObject && obj.opt(it) !is JSONArray }
            .map { key ->
                val value = obj.get(key).toString()
                CredentialField(
                    label = humanizeKey(key),
                    value = value,
                    mono = value.startsWith("http"),
                    good = key == "status" && value.lowercase() in setOf("active", "valid"),
                )
            }
            .sortedBy { orderIndex(it.label) }
            .toList()
        return fields.takeIf { it.isNotEmpty() }?.let { CredentialSection(header, it) }
    }

    private fun issuerSection(raw: JSONObject): CredentialSection? {
        val inst = raw.optJSONObject("institution")
        val fields = ArrayList<CredentialField>()
        inst?.keys()?.forEach { key ->
            if (inst.opt(key) is JSONObject || inst.opt(key) is JSONArray) return@forEach
            fields.add(CredentialField(humanizeKey(key), inst.get(key).toString()))
        }
        fields.sortBy { orderIndex(it.label) }
        raw.optString("iss").takeIf { it.isNotBlank() }
            ?.let { fields.add(CredentialField("Issuer URI", it, mono = true)) }
        return fields.takeIf { it.isNotEmpty() }?.let { CredentialSection("ISSUER", it) }
    }

    private fun validitySection(raw: JSONObject): CredentialSection? {
        val fields = ArrayList<CredentialField>()
        epochField(raw, "iat", "Issued")?.let(fields::add)
        epochField(raw, "exp", "Expires")?.let(fields::add)
        raw.optString("valid_until").takeIf { it.isNotBlank() }
            ?.let { fields.add(CredentialField("Valid until", it)) }
        raw.optString("conclusion_date").takeIf { it.isNotBlank() }
            ?.let { fields.add(CredentialField("Conclusion date", it)) }
        return fields.takeIf { it.isNotEmpty() }?.let { CredentialSection("VALIDITY", it) }
    }

    private fun revocationSection(raw: JSONObject): CredentialSection? {
        val sl = raw.optJSONObject("status")?.optJSONObject("status_list") ?: return null
        val fields = ArrayList<CredentialField>()
        fields.add(CredentialField("Current status", "Valid", good = true))
        if (sl.has("idx")) fields.add(CredentialField("Status list index", "#${sl.optInt("idx")}"))
        sl.optString("uri").takeIf { it.isNotBlank() }
            ?.let { fields.add(CredentialField("Status list", it, mono = true)) }
        return CredentialSection("REVOCATION STATUS", fields)
    }

    private fun keyBindingSection(raw: JSONObject): CredentialSection? {
        val jwk = raw.optJSONObject("cnf")?.optJSONObject("jwk") ?: return null
        val fields = ArrayList<CredentialField>()
        val keyType = listOf(jwk.optString("kty"), jwk.optString("crv")).filter { it.isNotBlank() }
        if (keyType.isNotEmpty()) fields.add(CredentialField("Key type", keyType.joinToString(" · ")))
        jwk.optString("x").takeIf { it.isNotBlank() }?.let { fields.add(CredentialField("Public key x", it, mono = true)) }
        jwk.optString("y").takeIf { it.isNotBlank() }?.let { fields.add(CredentialField("Public key y", it, mono = true)) }
        return fields.takeIf { it.isNotEmpty() }?.let { CredentialSection("KEY BINDING (CNF)", it) }
    }

    private fun epochField(raw: JSONObject, key: String, label: String): CredentialField? {
        if (!raw.has(key)) return null
        val seconds = raw.optLong(key, 0L)
        if (seconds <= 0L) return null
        val date = Instant.ofEpochSecond(seconds).atZone(ZoneId.systemDefault()).format(DATE_FMT)
        return CredentialField(label, date)
    }

    private val DATE_FMT: DateTimeFormatter = DateTimeFormatter.ofPattern("dd MMM yyyy")
    private val CAMEL_BOUNDARY = Regex("(?<=[a-z])(?=[A-Z])")
    private val HTTP_HOST = Regex("^https?://([^/]+)")

    private fun humanizeKey(key: String): String = SPECIAL_LABELS[key]
        ?: key.replace('_', ' ').replaceFirstChar { it.uppercase() }

    private fun orderIndex(label: String): Int =
        LEAF_ORDER.indexOf(label).let { if (it < 0) LEAF_ORDER.size else it }

    private val SPECIAL_LABELS = mapOf(
        "gpa" to "GPA",
        "emec_code" to "e-MEC code",
        "national_id" to "National ID",
        "student_id" to "Student ID",
        "date_of_birth" to "Date of birth",
        "field_of_study" to "Field of study",
        "workload_hours" to "Workload hours",
        "credits_completed" to "Credits completed",
        "enrollment_year" to "Enrollment year",
        "accreditation_act" to "Accreditation act",
        "graduation_date" to "Graduation date",
        "conclusion_date" to "Conclusion date",
        "registration_date" to "Registration date",
        "valid_until" to "Valid until",
    )

    /** Preferred display order of humanized field labels within a section. */
    private val LEAF_ORDER = listOf(
        "Full name", "Student ID", "National ID", "Date of birth", "Nationality", "Birthplace",
        "Enrollment year",
        "Title", "Level", "Field of study", "Modality", "Workload hours", "GPA",
        "Conclusion date", "Graduation date",
        "Program", "Semester", "Status", "Credits completed",
        "Name", "Acronym", "Country", "City", "State", "Type", "e-MEC code", "Accreditation act",
        "Number", "Book", "Page", "Registration date", "Registrar", "Valid until",
    )
}
