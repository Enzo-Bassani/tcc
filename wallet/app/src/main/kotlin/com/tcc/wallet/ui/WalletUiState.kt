package com.tcc.wallet.ui

import com.tcc.wallet.ssi.MatchedCredential
import com.tcc.wallet.ssi.QueryMatch
import com.tcc.wallet.ui.model.CredentialView
import org.json.JSONObject

enum class Screen { Home, Detail }

enum class ReceiveStep { Input, Offer, Done }

enum class PresentStep { Input, Select, Consent, Done }

enum class ScanMode { Receive, Present, Dispatch }

/** Receive (OID4VCI) bottom-sheet state; `null` in [WalletUiState] means it's closed. */
data class ReceiveState(
    val step: ReceiveStep = ReceiveStep.Input,
    val input: String = "",
    val issuerHost: String = "",
    val pending: CredentialView? = null, // received-but-not-yet-stored preview
)

/** Present (OID4VP) bottom-sheet state; `null` means it's closed. */
data class PresentState(
    val step: PresentStep = PresentStep.Input,
    val input: String = "",
    val request: JSONObject? = null,
    val queryMatches: List<QueryMatch> = emptyList(),
    val primaryQueryId: String = "",
    val matches: List<MatchedCredential> = emptyList(), // primary query's matches
    val candidates: List<CredentialView> = emptyList(), // matches mapped to display views
    val selectedIndex: Int = 0, // index into matches/candidates
    val verifierName: String = "Verifier",
    val verifierDomain: String = "",
    val verifierMonogram: String = "VF",
    val sharedCount: Int = 0,
) {
    val selectedMatch: MatchedCredential? get() = matches.getOrNull(selectedIndex)
    val selectedView: CredentialView? get() = candidates.getOrNull(selectedIndex)
}

data class ScannerState(val mode: ScanMode)

/** The single immutable screen-level state object (README "State Management"). */
data class WalletUiState(
    val screen: Screen = Screen.Home,
    val selectedCredentialId: String? = null,
    val credentials: List<CredentialView> = emptyList(),
    val receive: ReceiveState? = null,
    val present: PresentState? = null,
    val scanner: ScannerState? = null,
    val jsonVisible: Boolean = false,
    val toast: String? = null,
    val busy: Boolean = false,
) {
    val selectedCredential: CredentialView?
        get() = credentials.firstOrNull { it.id == selectedCredentialId }
}
