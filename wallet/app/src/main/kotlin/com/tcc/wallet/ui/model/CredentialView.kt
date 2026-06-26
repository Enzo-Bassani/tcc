package com.tcc.wallet.ui.model

import com.tcc.wallet.ui.theme.Gradient
import org.json.JSONObject

/** One field row in a detail section. [mono] renders the value in a monospace chip
 *  (URIs, key material); [good] renders it green (valid/active status). */
data class CredentialField(
    val label: String,
    val value: String,
    val mono: Boolean = false,
    val good: Boolean = false,
)

/** A titled group of fields in the credential detail view. */
data class CredentialSection(val header: String, val fields: List<CredentialField>)

/**
 * Everything the UI needs to render one stored credential, derived from the decoded
 * SD-JWT payload (`SsiEngine.readCredential`) — see [DisplayMapper]. Works for any
 * issued credential, not just the demo fixtures.
 */
data class CredentialView(
    val id: String,
    val sdJwt: String,
    val vct: String,
    val typeName: String,
    val issuerName: String,
    val holderName: String,
    val monogram: String,
    val accent: Gradient,
    val statusLabel: String,
    val sections: List<CredentialSection>,
    val rawJson: JSONObject,
)
