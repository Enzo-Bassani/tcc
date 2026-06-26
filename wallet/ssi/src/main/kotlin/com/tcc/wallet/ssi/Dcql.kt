package com.tcc.wallet.ssi

import org.json.JSONArray
import org.json.JSONObject

/**
 * The holder side of DCQL (OID4VP 1.0): given one credential query and the
 * wallet's full claim set, decide which claims to disclose — honoring
 * `claim_sets` preference order for data minimization. Mirrors
 * `ssi_core::dcql::CredentialQuery::resolve_required_paths` + the leaf-name
 * selection in `wallet_sim` (our issuer emits one disclosure per leaf claim, so
 * matching disclosures by leaf name is sufficient).
 */
object Dcql {

    /**
     * Leaf claim names to disclose for [credentialQuery] given [fullClaims], or
     * `null` if the credential can't satisfy the query (vct mismatch, or a
     * required claim is absent). An empty list means "no claims requested".
     */
    fun resolveWantedLeafNames(credentialQuery: JSONObject, fullClaims: JSONObject): List<String>? {
        if (!vctMatches(credentialQuery, fullClaims)) return null

        val claims = credentialQuery.optJSONArray("claims") ?: return emptyList()
        val all = (0 until claims.length()).map { claims.getJSONObject(it) }
        val claimSets = credentialQuery.optJSONArray("claim_sets")

        val chosen: List<JSONObject> = if (claimSets != null) {
            val byId = HashMap<String, JSONObject>()
            for (c in all) if (c.has("id")) byId[c.getString("id")] = c
            firstSatisfiableOption(claimSets, byId, fullClaims) ?: return null
        } else {
            if (!all.all { isSatisfiedBy(it, fullClaims) }) return null
            all
        }
        return chosen.mapNotNull { leafName(it) }
    }

    private fun firstSatisfiableOption(
        claimSets: JSONArray,
        byId: Map<String, JSONObject>,
        fullClaims: JSONObject,
    ): List<JSONObject>? {
        for (s in 0 until claimSets.length()) {
            val option = claimSets.getJSONArray(s)
            val set = ArrayList<JSONObject>()
            var resolvable = true
            for (j in 0 until option.length()) {
                val c = byId[option.getString(j)]
                if (c == null) { resolvable = false; break }
                set.add(c)
            }
            if (resolvable && set.all { isSatisfiedBy(it, fullClaims) }) return set
        }
        return null
    }

    private fun vctMatches(query: JSONObject, claims: JSONObject): Boolean {
        val values = query.optJSONObject("meta")?.optJSONArray("vct_values") ?: return true
        if (!claims.has("vct")) return false
        val vct = claims.getString("vct")
        return (0 until values.length()).any { values.getString(it) == vct }
    }

    private fun isSatisfiedBy(claim: JSONObject, claims: JSONObject): Boolean =
        select(claims, claim.getJSONArray("path")).isNotEmpty()

    private fun leafName(claim: JSONObject): String? {
        val path = claim.getJSONArray("path")
        if (path.length() == 0) return null
        return path.get(path.length() - 1) as? String
    }

    /**
     * DCQL Claims Path Pointer (the subset we need): a string selects an object
     * key, a number selects an array index, `null` selects every array element.
     */
    private fun select(root: Any?, path: JSONArray): List<Any?> {
        var current = listOf<Any?>(root)
        for (i in 0 until path.length()) {
            val element = path.get(i)
            val next = ArrayList<Any?>()
            for (node in current) {
                when {
                    element is String ->
                        if (node is JSONObject && node.has(element) && !node.isNull(element)) next.add(node.get(element))
                    element is Number ->
                        if (node is JSONArray && element.toInt() < node.length()) next.add(node.get(element.toInt()))
                    element === JSONObject.NULL ->
                        if (node is JSONArray) for (k in 0 until node.length()) next.add(node.get(k))
                }
            }
            current = next
        }
        return current
    }
}
