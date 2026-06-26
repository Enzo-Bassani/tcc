package com.tcc.wallet.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.tcc.wallet.WalletStore
import com.tcc.wallet.ssi.SsiEngine
import com.tcc.wallet.ssi.StoredCredential
import android.net.Uri
import com.tcc.wallet.ssi.net.Http
import com.tcc.wallet.ssi.net.Oid4vciClient
import com.tcc.wallet.ssi.net.Oid4vpPresenter
import com.tcc.wallet.ssi.net.OfferLink
import com.tcc.wallet.ssi.net.ScanDispatch
import com.tcc.wallet.ui.model.DisplayMapper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** One-shot side effects the UI host (MainActivity) must act on — fired once, not state. */
sealed interface WalletEffect {
    /** Open the OID4VCI authorization endpoint in a browser (Custom Tab) for SSO login. */
    data class OpenBrowser(val url: String) : WalletEffect
}

/**
 * Drives the whole wallet UI off the **real** SSI flows (`:ssi`): OID4VCI receive and
 * OID4VP present. All network/crypto runs off [viewModelScope] on [Dispatchers.IO];
 * the UI observes a single [WalletUiState].
 */
class WalletViewModel(
    private val store: WalletStore,
    private val engine: SsiEngine,
) : ViewModel() {

    private val http = Http()
    private val presenter = Oid4vpPresenter(http, engine)

    private val _state = MutableStateFlow(WalletUiState())
    val state: StateFlow<WalletUiState> = _state.asStateFlow()

    private val _effects = Channel<WalletEffect>(Channel.BUFFERED)
    val effects = _effects.receiveAsFlow()

    /** Pending OID4VCI authorization-code flow, held across the browser trip (in-memory
     *  only; process-death persistence is deferred). */
    private var authPending: Oid4vciClient.AuthPending? = null

    init {
        reloadCredentials()
    }

    private fun reloadCredentials() {
        val views = store.credentials().mapNotNull { runCatching { DisplayMapper.from(it, engine) }.getOrNull() }
        _state.update { it.copy(credentials = views) }
    }

    // --- navigation -----------------------------------------------------------

    fun openCredential(id: String) = _state.update { it.copy(screen = Screen.Detail, selectedCredentialId = id) }
    fun back() = _state.update { it.copy(screen = Screen.Home, selectedCredentialId = null, jsonVisible = false) }

    fun showJson() = _state.update { it.copy(jsonVisible = true) }
    fun hideJson() = _state.update { it.copy(jsonVisible = false) }

    fun setToast(message: String) = _state.update { it.copy(toast = message) }
    fun dismissToast() = _state.update { it.copy(toast = null) }

    // --- receive (OID4VCI) ----------------------------------------------------

    fun closeReceive() = _state.update { it.copy(receive = null) }
    fun receiveInput(text: String) = _state.update { it.copy(receive = (it.receive ?: ReceiveState()).copy(input = text)) }

    fun receiveContinue() = doReceive(_state.value.receive?.input.orEmpty())

    private fun doReceive(offerText: String) {
        if (offerText.isBlank()) return
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            val resolved = withContext(Dispatchers.IO) { runCatching { OfferLink.resolve(offerText, http) } }
            resolved
                .onSuccess { offer ->
                    when (Oid4vciClient.detectGrant(offer)) {
                        Oid4vciClient.Grant.PreAuthorized -> runPreAuth(offer, offerText)
                        Oid4vciClient.Grant.AuthorizationCode -> startAuthCode(offer)
                    }
                }
                .onFailure { e -> failWithError("Receive failed", e) }
        }
    }

    /** Pre-authorized grant: a single round-trip, no browser. */
    private fun runPreAuth(offer: JSONObject, offerText: String) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { Oid4vciClient(http).receive(offer, store.holder, engine) }
            }
            result
                .onSuccess { sdJwt -> showReceivedPreview(sdJwt, offerText) }
                .onFailure { e -> failWithError("Receive failed", e) }
        }
    }

    /** Authorization-code grant: prepare PKCE + authorize URL, then hand off to the browser. */
    private fun startAuthCode(offer: JSONObject) {
        viewModelScope.launch {
            val prepared = withContext(Dispatchers.IO) {
                runCatching { Oid4vciClient(http).prepareAuthorization(offer, REDIRECT_URI) }
            }
            prepared
                .onSuccess { pending ->
                    authPending = pending
                    _state.update { it.copy(busy = false) } // leaving for the browser
                    _effects.send(WalletEffect.OpenBrowser(pending.authorizationUrl))
                }
                .onFailure { e -> failWithError("Authorization setup failed", e) }
        }
    }

    /** Resume the authorization-code flow from the `com.tcc.wallet://oid4vci` redirect. */
    fun onAuthCallback(uri: Uri) {
        val pending = authPending
        if (pending == null) {
            _state.update { it.copy(busy = false, toast = "No authorization in progress") }
            return
        }
        uri.getQueryParameter("error")?.let { return finishAuth(toast = "Authorization error: $it") }
        val returnedState = uri.getQueryParameter("state")
        if (returnedState == null || returnedState != pending.state) {
            return finishAuth(toast = "Authorization state mismatch")
        }
        val code = uri.getQueryParameter("code")
        if (code.isNullOrBlank()) return finishAuth(toast = "No authorization code returned")
        // RFC 9207 (HAIP §4): the AS echoes its issuer identifier; the client verifies
        // it inside completeAuthorization (rejects on absence/mismatch).
        val returnedIss = uri.getQueryParameter("iss")

        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    Oid4vciClient(http).completeAuthorization(pending, code, returnedIss, store.holder, engine)
                }
            }
            authPending = null
            result
                .onSuccess { sdJwt -> showReceivedPreview(sdJwt, offerText = "") }
                .onFailure { e -> failWithError("Receive failed", e) }
        }
    }

    /** Clear the pending auth, close the receive sheet, and surface a message. */
    private fun finishAuth(toast: String) {
        authPending = null
        _state.update { it.copy(busy = false, receive = null, toast = toast) }
    }

    /** Stop the spinner and toast a "<prefix>: <reason>" failure (the one error-surfacing path). */
    private fun failWithError(prefix: String, e: Throwable) =
        _state.update { it.copy(busy = false, toast = "$prefix: ${e.message}") }

    /** Show a freshly-received (not yet stored) credential in the receive sheet preview. */
    private fun showReceivedPreview(sdJwt: String, offerText: String) {
        val view = DisplayMapper.from(sdJwt, engine)
        val host = hostOf(view.rawJson.optString("iss")).ifBlank { view.issuerName }
        _state.update {
            it.copy(
                busy = false,
                receive = (it.receive ?: ReceiveState()).copy(
                    step = ReceiveStep.Offer,
                    input = offerText.ifBlank { it.receive?.input.orEmpty() },
                    pending = view,
                    issuerHost = host,
                ),
            )
        }
    }

    fun receiveAccept() {
        val pending = _state.value.receive?.pending ?: return
        store.addCredential(pending.sdJwt)
        reloadCredentials()
        _state.update { it.copy(receive = it.receive?.copy(step = ReceiveStep.Done)) }
    }

    // --- present (OID4VP) -----------------------------------------------------

    fun closePresent() = _state.update { it.copy(present = null) }
    fun presentInput(text: String) = _state.update { it.copy(present = (it.present ?: PresentState()).copy(input = text)) }

    fun presentContinue() = doPresent(_state.value.present?.input.orEmpty().trim())

    private fun doPresent(requestText: String) {
        if (requestText.isBlank()) return
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            val wallet = store.credentials().map { StoredCredential(it, store.holder) }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val scanned = presenter.parseQr(requestText)
                    val req = presenter.verifyRequest(scanned)
                    req to engine.findMatches(req, wallet)
                }
            }
            result
                .onSuccess { (req, queryMatches) ->
                    val primary = queryMatches.firstOrNull { it.matches.isNotEmpty() }
                    if (primary == null) {
                        _state.update {
                            it.copy(busy = false, toast = "No stored credential satisfies this request")
                        }
                        return@onSuccess
                    }
                    val candidates = primary.matches.map { DisplayMapper.from(it.sdJwt, engine) }
                    val multiple = primary.matches.size > 1
                    val verifier = verifierIdentity(req)
                    _state.update {
                        it.copy(
                            busy = false,
                            present = (it.present ?: PresentState()).copy(
                                step = if (multiple) PresentStep.Select else PresentStep.Consent,
                                input = requestText,
                                request = req,
                                queryMatches = queryMatches,
                                primaryQueryId = primary.queryId,
                                matches = primary.matches,
                                candidates = candidates,
                                selectedIndex = 0,
                                verifierName = verifier.first,
                                verifierDomain = verifier.second,
                                verifierMonogram = verifier.third,
                            ),
                        )
                    }
                }
                .onFailure { e -> failWithError("Verify failed", e) }
        }
    }

    fun selectMatch(index: Int) = _state.update { it.copy(present = it.present?.copy(selectedIndex = index)) }
    fun presentSelectContinue() = _state.update { it.copy(present = it.present?.copy(step = PresentStep.Consent)) }
    fun backToSelect() = _state.update { it.copy(present = it.present?.copy(step = PresentStep.Select)) }

    fun presentShare() {
        val present = _state.value.present ?: return
        val req = present.request ?: return
        val chosen = present.selectedMatch ?: return
        val selection = buildMap {
            for (qm in present.queryMatches) {
                if (qm.matches.isEmpty()) continue
                val idx = if (qm.queryId == present.primaryQueryId) chosen.index else qm.matches.first().index
                put(qm.queryId, idx)
            }
        }
        _state.update { it.copy(busy = true) }
        viewModelScope.launch {
            val wallet = store.credentials().map { StoredCredential(it, store.holder) }
            val result = withContext(Dispatchers.IO) {
                runCatching { presenter.present(req, wallet, selection) }
            }
            result
                .onSuccess {
                    _state.update {
                        it.copy(
                            busy = false,
                            present = it.present?.copy(step = PresentStep.Done, sharedCount = chosen.disclosed.size),
                        )
                    }
                }
                .onFailure { e -> failWithError("Present failed", e) }
        }
    }

    fun presentDeny() = _state.update { it.copy(present = null, toast = "Request declined") }

    // --- scanner --------------------------------------------------------------

    /** The unified home action: open the scanner and auto-route whatever it reads. */
    fun openScan() = _state.update { it.copy(scanner = ScannerState(ScanMode.Dispatch)) }

    fun openScanner(mode: ScanMode) = _state.update { it.copy(scanner = ScannerState(mode)) }
    fun cancelScanner() = _state.update { it.copy(scanner = null) }

    fun onScanned(text: String) {
        val mode = _state.value.scanner?.mode ?: return
        _state.update { it.copy(scanner = null) }
        when (mode) {
            ScanMode.Receive -> {
                _state.update { it.copy(receive = (it.receive ?: ReceiveState()).copy(input = text)) }
                doReceive(text)
            }
            ScanMode.Present -> {
                _state.update { it.copy(present = (it.present ?: PresentState()).copy(input = text.trim())) }
                doPresent(text.trim())
            }
            ScanMode.Dispatch -> dispatch(text)
        }
    }

    /** Classify a scanned/pasted/deep-linked value and start the matching flow. */
    fun dispatch(text: String) {
        when (ScanDispatch.classify(text)) {
            ScanDispatch.Kind.Issuance -> {
                _state.update { it.copy(receive = ReceiveState(input = text)) }
                doReceive(text)
            }
            ScanDispatch.Kind.Presentation -> {
                _state.update { it.copy(present = PresentState(input = text.trim())) }
                doPresent(text.trim())
            }
            ScanDispatch.Kind.Unknown -> _state.update { it.copy(toast = "Unrecognized QR code or link") }
        }
    }

    // --- helpers --------------------------------------------------------------

    /** (name, domain, monogram) for the verifier consent card, from the verified request. */
    private fun verifierIdentity(req: JSONObject): Triple<String, String, String> {
        val domain = hostOf(req.optString("response_uri")).ifBlank { hostOf(req.optString("client_id")) }
        val name = req.optJSONObject("client_metadata")?.optString("client_name")
            ?.takeUnless { it.isBlank() } ?: domain.ifBlank { "Verifier" }
        return Triple(name, domain, initials(name))
    }

    private fun hostOf(uri: String): String =
        SCHEME_HOST.find(uri)?.groupValues?.get(1) ?: ""

    private fun initials(name: String): String {
        val letters = name.filter { it.isLetterOrDigit() || it == ' ' }.split(' ').filter { it.isNotBlank() }
        return letters.take(2).joinToString("") { it.first().uppercaseChar().toString() }.ifBlank { "VF" }
    }

    class Factory(
        private val store: WalletStore,
        private val engine: SsiEngine,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T =
            WalletViewModel(store, engine) as T
    }

    companion object {
        /** Wallet redirect for the OID4VCI authorization-code flow; registered in the manifest. */
        const val REDIRECT_URI = "com.tcc.wallet://oid4vci"

        private val SCHEME_HOST = Regex("^[a-z]+://([^/]+)")
    }
}
