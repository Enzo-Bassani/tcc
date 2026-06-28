package com.tcc.wallet

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import com.tcc.wallet.ssi.RustSsiEngine
import com.tcc.wallet.ssi.SsiEngine
import com.tcc.wallet.ui.Screen
import com.tcc.wallet.ui.WalletEffect
import com.tcc.wallet.ui.WalletViewModel
import com.tcc.wallet.ui.screens.CredentialDetailScreen
import com.tcc.wallet.ui.screens.HomeScreen
import com.tcc.wallet.ui.screens.JsonSheet
import com.tcc.wallet.ui.screens.PresentSheet
import com.tcc.wallet.ui.screens.ReceiveSheet
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletTheme
import kotlinx.coroutines.launch
import java.io.File

/**
 * Single-activity host. Builds the device-bound holder key + persistent store, then hands
 * a [WalletViewModel] to the Compose UI ([WalletRoot]). The UI (home · detail · receive ·
 * present · scanner · JSON) is driven entirely by the real `:ssi` flows. Deep links
 * (`openid-credential-offer://` / `openid4vp://`) feed the VM on first launch.
 *
 * The VM is hoisted to an Activity-scoped field (not a Compose-local `viewModel(...)`) so
 * [onNewIntent] — which delivers the OID4VCI authorization-code redirect — and Compose
 * share the **same** instance, preserving the in-memory pending-auth across the browser trip.
 */
class MainActivity : ComponentActivity() {

    private val holder by lazy { KeystoreHolderKey.getOrCreate(this) }
    private val store by lazy { WalletStore(File(filesDir, "wallet.json"), holder) }
    private val engine: SsiEngine by lazy { RustSsiEngine() }
    private val vm: WalletViewModel by viewModels { WalletViewModel.Factory(store, engine) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            WalletTheme {
                LaunchedEffect(Unit) {
                    // Start collecting before routing, so an effect from the initial intent
                    // (e.g. a cold-start auth-code offer) is observed rather than just buffered.
                    launch {
                        vm.effects.collect { effect ->
                            when (effect) {
                                is WalletEffect.OpenBrowser ->
                                    CustomTabsIntent.Builder().build()
                                        .launchUrl(this@MainActivity, Uri.parse(effect.url))
                            }
                        }
                    }
                    routeIntent(intent)
                }
                WalletRoot(vm)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        routeIntent(intent)
    }

    /** Dispatch an inbound deep link / authorization-code redirect to the VM. */
    private fun routeIntent(intent: Intent?) {
        val data = intent?.data ?: return
        when (data.scheme) {
            // The auth-code redirect resumes pending state, so it bypasses content dispatch.
            "com.tcc.wallet" -> vm.onAuthCallback(data)
            "openid-credential-offer", "openid4vp" -> vm.dispatch(data.toString())
        }
    }
}

@Composable
private fun WalletRoot(vm: WalletViewModel) {
    val state by vm.state.collectAsState()
    val clipboard = LocalClipboardManager.current

    Surface(Modifier.fillMaxSize(), color = WalletColors.AppBg) {
        Box(Modifier.fillMaxSize()) {
            // Base screen (Home ⇄ Detail).
            when (state.screen) {
                Screen.Home -> HomeScreen(
                    state = state,
                    onOpenCredential = vm::openCredential,
                    onScan = vm::openScan,
                )
                Screen.Detail -> {
                    val credential = state.selectedCredential
                    if (credential == null) {
                        HomeScreen(state, vm::openCredential, vm::openScan)
                    } else {
                        CredentialDetailScreen(
                            credential = credential,
                            onBack = vm::back,
                            onVerify = { vm.setToast("Status verified · Valid") },
                            onViewJson = vm::showJson,
                        )
                    }
                }
            }

            // Overlays, in the README's z-order (sheets · scanner · JSON · toast).
            state.receive?.let { receive ->
                ReceiveSheet(
                    state = receive,
                    busy = state.busy,
                    onClose = vm::closeReceive,
                    onInput = vm::receiveInput,
                    onScan = { vm.openScanner(com.tcc.wallet.ui.ScanMode.Receive) },
                    onContinue = vm::receiveContinue,
                    onAccept = vm::receiveAccept,
                )
            }
            state.present?.let { present ->
                PresentSheet(
                    state = present,
                    busy = state.busy,
                    onClose = vm::closePresent,
                    onInput = vm::presentInput,
                    onScan = { vm.openScanner(com.tcc.wallet.ui.ScanMode.Present) },
                    onContinue = vm::presentContinue,
                    onSelect = vm::selectMatch,
                    onSelectContinue = vm::presentSelectContinue,
                    onBackToSelect = vm::backToSelect,
                    onShare = vm::presentShare,
                    onDeny = vm::presentDeny,
                )
            }
            state.scanner?.let {
                QrScanner(onResult = vm::onScanned, onCancel = vm::cancelScanner)
            }
            if (state.jsonVisible) {
                state.selectedCredential?.let { credential ->
                    JsonSheet(
                        credential = credential,
                        onClose = vm::hideJson,
                        onCopy = { text ->
                            clipboard.setText(AnnotatedString(text))
                            vm.setToast("JSON copied to clipboard")
                        },
                    )
                }
            }
            state.toast?.let { message ->
                com.tcc.wallet.ui.components.Toast(message)
                LaunchedEffect(message) {
                    kotlinx.coroutines.delay(2400)
                    vm.dismissToast()
                }
            }
        }
    }
}
