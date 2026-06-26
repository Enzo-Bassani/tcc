package com.tcc.wallet.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.SouthWest
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.tcc.wallet.ui.ReceiveState
import com.tcc.wallet.ui.ReceiveStep
import com.tcc.wallet.ui.components.DarkButton
import com.tcc.wallet.ui.components.Monogram
import com.tcc.wallet.ui.components.MonoTextField
import com.tcc.wallet.ui.components.OrDivider
import com.tcc.wallet.ui.components.OutlinedActionButton
import com.tcc.wallet.ui.components.PrimaryButton
import com.tcc.wallet.ui.components.SheetHeader
import com.tcc.wallet.ui.components.SheetOverlay
import com.tcc.wallet.ui.components.SuccessStep
import com.tcc.wallet.ui.components.VerifiedBadge
import com.tcc.wallet.ui.model.CredentialView
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletShapes
import com.tcc.wallet.ui.theme.WalletType

@Composable
fun ReceiveSheet(
    state: ReceiveState,
    busy: Boolean,
    onClose: () -> Unit,
    onInput: (String) -> Unit,
    onScan: () -> Unit,
    onContinue: () -> Unit,
    onAccept: () -> Unit,
) {
    SheetOverlay(onDismiss = onClose) {
        SheetHeader(
            icon = Icons.Rounded.SouthWest,
            title = "Receive a credential",
            protocol = "OID4VCI",
            onClose = onClose,
        )
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(start = 20.dp, end = 20.dp, bottom = 26.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            when (state.step) {
                ReceiveStep.Input -> InputStep(state, busy, onInput, onScan, onContinue)
                ReceiveStep.Offer -> OfferStep(state, busy, onClose, onAccept)
                ReceiveStep.Done -> DoneStep(state, onClose)
            }
        }
    }
}

@Composable
private fun InputStep(
    state: ReceiveState,
    busy: Boolean,
    onInput: (String) -> Unit,
    onScan: () -> Unit,
    onContinue: () -> Unit,
) {
    Text(
        "Paste the issuer's credential offer link, or scan its QR code, to receive a verifiable credential.",
        style = WalletType.body,
    )
    Text("OFFER LINK OR JSON", style = WalletType.inputLabel)
    MonoTextField(state.input, onInput, placeholder = "openid-credential-offer://…")
    OrDivider()
    OutlinedActionButton(
        "Scan QR code",
        Modifier.fillMaxWidth(),
        enabled = !busy,
        icon = Icons.Rounded.QrCodeScanner,
        textColor = WalletColors.Ink,
        onClick = onScan,
    )
    PrimaryButton("Continue", Modifier.fillMaxWidth(), enabled = !busy && state.input.isNotBlank(), onClick = onContinue)
}

@Composable
private fun OfferStep(state: ReceiveState, busy: Boolean, onClose: () -> Unit, onAccept: () -> Unit) {
    val pending = state.pending
    Text(
        "${state.issuerHost.ifBlank { "The issuer" }} wants to issue you",
        style = WalletType.bodySmall,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth(),
    )
    if (pending != null) OfferPreview(pending)
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Icon(Icons.Rounded.Lock, contentDescription = null, tint = WalletColors.Success, modifier = Modifier.size(15.dp))
        Text(
            "Issuer signature verified · key-bound to this device",
            style = WalletType.bodySmall.copy(color = WalletColors.Success),
        )
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(11.dp)) {
        OutlinedActionButton("Decline", Modifier.weight(1f), enabled = !busy, textColor = WalletColors.Ink, onClick = onClose)
        PrimaryButton("Add to wallet", Modifier.weight(1f), enabled = !busy, onClick = onAccept)
    }
}

@Composable
private fun OfferPreview(pending: CredentialView) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(WalletShapes.card)
            .background(WalletColors.Surface)
            .border(1.dp, WalletColors.Hairline, WalletShapes.card)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Monogram(pending.monogram, pending.accent, size = 44.dp, corner = 12.dp)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(pending.typeName, style = WalletType.cardTitle)
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(pending.issuerName, style = WalletType.cardIssuer)
                    VerifiedBadge(12.dp)
                }
            }
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(WalletColors.Divider))
        pending.sections.asSequence().flatMap { it.fields.asSequence() }
            .filter { !it.mono }
            .take(4)
            .forEach { field ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(field.label, style = WalletType.fieldLabel)
                    Text(
                        field.value,
                        style = WalletType.fieldValue,
                        textAlign = TextAlign.End,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
    }
}

@Composable
private fun DoneStep(state: ReceiveState, onClose: () -> Unit) {
    SuccessStep(
        title = "Added to wallet",
        body = "${state.pending?.typeName ?: "The credential"} is now stored securely on your device.",
    )
    DarkButton("Done", Modifier.fillMaxWidth(), onClick = onClose)
}
