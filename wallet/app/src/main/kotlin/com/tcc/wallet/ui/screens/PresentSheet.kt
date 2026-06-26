package com.tcc.wallet.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.ChevronLeft
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.NorthEast
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.tcc.wallet.ssi.DisclosedClaim
import com.tcc.wallet.ui.PresentState
import com.tcc.wallet.ui.PresentStep
import com.tcc.wallet.ui.components.LinkText
import com.tcc.wallet.ui.components.Monogram
import com.tcc.wallet.ui.components.MonoTextField
import com.tcc.wallet.ui.components.OrDivider
import com.tcc.wallet.ui.components.OutlinedActionButton
import com.tcc.wallet.ui.components.PrimaryButton
import com.tcc.wallet.ui.components.SheetHeader
import com.tcc.wallet.ui.components.SheetOverlay
import com.tcc.wallet.ui.components.SuccessStep
import com.tcc.wallet.ui.components.DarkButton
import com.tcc.wallet.ui.model.CredentialView
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletShapes
import com.tcc.wallet.ui.theme.WalletType

@Composable
fun PresentSheet(
    state: PresentState,
    busy: Boolean,
    onClose: () -> Unit,
    onInput: (String) -> Unit,
    onScan: () -> Unit,
    onContinue: () -> Unit,
    onSelect: (Int) -> Unit,
    onSelectContinue: () -> Unit,
    onBackToSelect: () -> Unit,
    onShare: () -> Unit,
    onDeny: () -> Unit,
) {
    SheetOverlay(onDismiss = onClose) {
        SheetHeader(
            icon = Icons.Rounded.NorthEast,
            title = "Present a credential",
            protocol = "OID4VP",
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
                PresentStep.Input -> InputStep(state, busy, onInput, onScan, onContinue)
                PresentStep.Select -> SelectStep(state, onSelect, onSelectContinue)
                PresentStep.Consent -> ConsentStep(state, busy, onBackToSelect, onShare, onDeny)
                PresentStep.Done -> DoneStep(state, onClose)
            }
        }
    }
}

@Composable
private fun InputStep(
    state: PresentState,
    busy: Boolean,
    onInput: (String) -> Unit,
    onScan: () -> Unit,
    onContinue: () -> Unit,
) {
    Text(
        "Paste the verifier's presentation request, or scan its QR code, to choose what to share.",
        style = WalletType.body,
    )
    Text("REQUEST URI", style = WalletType.inputLabel)
    MonoTextField(state.input, onInput, placeholder = "openid4vp://?request_uri=…")
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
private fun SelectStep(state: PresentState, onSelect: (Int) -> Unit, onSelectContinue: () -> Unit) {
    com.tcc.wallet.ui.components.VerifierCard(state.verifierName, state.verifierDomain, state.verifierMonogram)
    Text(
        "More than one credential satisfies this request. Choose which one to present:",
        style = WalletType.bodySmall,
    )
    state.candidates.forEachIndexed { index, candidate ->
        SelectableCredential(candidate, distinguishingLine(candidate), selected = index == state.selectedIndex) { onSelect(index) }
    }
    PrimaryButton("Continue", Modifier.fillMaxWidth(), onClick = onSelectContinue)
}

/** A line that tells same-type credentials apart in the picker — the degree/program
 *  title when present, else the holder name. */
private fun distinguishingLine(candidate: CredentialView): String {
    val title = candidate.sections.asSequence()
        .flatMap { it.fields.asSequence() }
        .firstOrNull { it.label == "Title" || it.label == "Program" }
        ?.value
    return title ?: candidate.holderName
}

@Composable
private fun SelectableCredential(candidate: CredentialView, detail: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(WalletShapes.card)
            .background(if (selected) WalletColors.SelectedBg else WalletColors.Surface)
            .border(
                width = if (selected) 2.dp else 1.5.dp,
                color = if (selected) WalletColors.Brand else WalletColors.Hairline,
                shape = WalletShapes.card,
            )
            .clickable { onClick() }
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Monogram(candidate.monogram, candidate.accent, size = 42.dp, corner = 11.dp)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(candidate.typeName, style = WalletType.cardTitle)
            Text(candidate.issuerName, style = WalletType.cardIssuer)
            if (detail.isNotBlank()) {
                Text(detail, style = WalletType.cardHolder)
            }
        }
        RadioDot(selected)
    }
}

@Composable
private fun RadioDot(selected: Boolean) {
    if (selected) {
        Box(
            Modifier.size(24.dp).clip(CircleShape).background(WalletColors.Brand),
            contentAlignment = Alignment.Center,
        ) { Icon(Icons.Rounded.Check, contentDescription = "selected", tint = WalletColors.Surface, modifier = Modifier.size(15.dp)) }
    } else {
        Box(Modifier.size(24.dp).clip(CircleShape).border(2.dp, WalletColors.SecondaryBorder, CircleShape))
    }
}

@Composable
private fun ConsentStep(
    state: PresentState,
    busy: Boolean,
    onBackToSelect: () -> Unit,
    onShare: () -> Unit,
    onDeny: () -> Unit,
) {
    val asked = state.selectedMatch?.disclosed.orEmpty()
    val alwaysShared = state.selectedMatch?.alwaysShared.orEmpty()
    val typeName = state.selectedView?.typeName ?: "credential"

    com.tcc.wallet.ui.components.VerifierCard(state.verifierName, state.verifierDomain, state.verifierMonogram)
    Text(
        buildAnnotatedString {
            append("wants to read data from your ")
            withStyle(SpanStyle(fontWeight = FontWeight(800), color = WalletColors.Ink)) { append(typeName) }
            append(".")
        },
        style = WalletType.bodySmall,
    )
    if (state.matches.size > 1) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Rounded.ChevronLeft, contentDescription = null, tint = WalletColors.Brand, modifier = Modifier.size(16.dp))
            LinkText("Choose a different credential", onBackToSelect)
        }
    }

    // Group 1 — what the verifier explicitly asked for (the selective disclosures).
    GroupHeader("WHAT'S BEING ASKED")
    AttributeCard(asked, Icons.Rounded.Check, WalletColors.Brand)
    Caption("${asked.size} attribute${plural(asked.size)} requested · the verifier receives all or nothing.")

    // Group 2 — what always travels with the credential and cannot be withheld.
    if (alwaysShared.isNotEmpty()) {
        GroupHeader("ALSO SHARED BY DEFAULT")
        AttributeCard(alwaysShared, Icons.Rounded.Lock, WalletColors.Faint)
        Caption(
            "Part of the signed credential — it goes to the verifier whenever you present this " +
                "credential and cannot be left out.",
        )
    }

    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(11.dp)) {
        OutlinedActionButton("Deny", Modifier.weight(1f), enabled = !busy, textColor = WalletColors.Ink, onClick = onDeny)
        PrimaryButton("Share", Modifier.weight(1f), enabled = !busy && asked.isNotEmpty(), onClick = onShare)
    }
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Rounded.Lock, contentDescription = null, tint = WalletColors.Faint, modifier = Modifier.size(13.dp))
        Text(
            "  Everything shown above leaves your device when you tap Share",
            style = WalletType.bodySmall.copy(color = WalletColors.Faint),
        )
    }
}

@Composable
private fun GroupHeader(text: String) {
    Text(text, style = WalletType.sectionHeader, modifier = Modifier.padding(start = 4.dp, top = 4.dp))
}

@Composable
private fun Caption(text: String) {
    Text(text, style = WalletType.bodySmall.copy(color = WalletColors.Faint), modifier = Modifier.padding(horizontal = 4.dp))
}

private fun plural(n: Int): String = if (n == 1) "" else "s"

@Composable
private fun AttributeCard(claims: List<DisclosedClaim>, icon: androidx.compose.ui.graphics.vector.ImageVector, iconTint: androidx.compose.ui.graphics.Color) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(WalletShapes.card)
            .background(WalletColors.Surface)
            .border(1.dp, WalletColors.Hairline, WalletShapes.card)
            .padding(horizontal = 16.dp),
    ) {
        claims.forEachIndexed { i, claim ->
            Row(
                Modifier.fillMaxWidth().padding(vertical = 13.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(claim.label, style = WalletType.fieldLabel)
                    Text(claim.value, style = WalletType.fieldValue)
                }
                Icon(icon, contentDescription = null, tint = iconTint, modifier = Modifier.size(18.dp))
            }
            if (i != claims.lastIndex) {
                Box(Modifier.fillMaxWidth().height(1.dp).background(WalletColors.Divider))
            }
        }
    }
}

@Composable
private fun DoneStep(state: PresentState, onClose: () -> Unit) {
    SuccessStep(
        title = "Credential shared",
        body = "Shared ${state.sharedCount} attribute${if (state.sharedCount == 1) "" else "s"} with ${state.verifierName}.",
    )
    DarkButton("Done", Modifier.fillMaxWidth(), onClick = onClose)
}
