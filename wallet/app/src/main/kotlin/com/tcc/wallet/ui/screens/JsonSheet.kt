package com.tcc.wallet.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.tcc.wallet.ui.components.OutlinedActionButton
import com.tcc.wallet.ui.components.SheetHeader
import com.tcc.wallet.ui.components.SheetOverlay
import com.tcc.wallet.ui.components.highlightJson
import com.tcc.wallet.ui.model.CredentialView
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletType

/** The dark "Technical view" sheet: syntax-highlighted decoded SD-JWT payload + Copy. */
@Composable
fun JsonSheet(credential: CredentialView, onClose: () -> Unit, onCopy: (String) -> Unit) {
    val pretty = remember(credential.id) { credential.rawJson.toString(2) }
    val highlighted = remember(credential.id) { highlightJson(pretty) }
    SheetOverlay(onDismiss = onClose, dark = true, heightFraction = 0.8f) {
        SheetHeader(
            icon = Icons.Rounded.Code,
            title = "Technical view",
            protocol = "SD-JWT VC · decoded payload",
            onClose = onClose,
            dark = true,
        )
        Column(
            Modifier
                .weight(1f)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 18.dp, vertical = 4.dp),
        ) {
            Text(highlighted, style = WalletType.json.copy(color = Color(0xFFE5E9F0)))
        }
        Column(Modifier.fillMaxWidth().padding(start = 18.dp, end = 18.dp, top = 12.dp, bottom = 24.dp)) {
            OutlinedActionButton(
                "Copy JSON",
                Modifier.fillMaxWidth(),
                icon = Icons.Rounded.ContentCopy,
                textColor = WalletColors.Ink,
                onClick = { onCopy(pretty) },
            )
        }
    }
}
