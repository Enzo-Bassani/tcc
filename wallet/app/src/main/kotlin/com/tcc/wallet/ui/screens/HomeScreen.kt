package com.tcc.wallet.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.PersonOutline
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.unit.dp
import com.tcc.wallet.ui.WalletUiState
import com.tcc.wallet.ui.components.CredentialCard
import com.tcc.wallet.ui.components.PrimaryButton
import com.tcc.wallet.ui.theme.BrandGradient
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletType

@Composable
fun HomeScreen(
    state: WalletUiState,
    onOpenCredential: (String) -> Unit,
    onScan: () -> Unit,
) {
    Box(Modifier.fillMaxSize().background(WalletColors.AppBg)) {
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 14.dp, bottom = 120.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            item { BrandRow() }
            item {
                Column(Modifier.padding(top = 10.dp)) {
                    Text("Your credentials", style = WalletType.screenTitle)
                    Spacer(Modifier.height(4.dp))
                    Text(countLabel(state.credentials.size), style = WalletType.screenSubtitle)
                }
            }
            item { Spacer(Modifier.height(10.dp)) }

            if (state.credentials.isEmpty()) {
                item { EmptyState() }
            } else {
                items(state.credentials, key = { it.id }) { cred ->
                    CredentialCard(cred) { onOpenCredential(cred.id) }
                }
            }
        }

        // Pinned, gradient-faded action bar.
        Column(
            Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .background(Brush.verticalGradient(listOf(WalletColors.AppBg.copy(alpha = 0f), WalletColors.AppBg)))
                .padding(start = 20.dp, end = 20.dp, top = 18.dp, bottom = 24.dp),
        ) {
            // One button drives both flows: scan (or paste) an offer or a request,
            // and the wallet routes by content (ScanDispatch).
            PrimaryButton("Scan", Modifier.fillMaxWidth(), icon = Icons.Rounded.QrCodeScanner, onClick = onScan)
        }
    }
}

@Composable
private fun BrandRow() {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(34.dp).clip(RoundedCornerShape(10.dp)).background(BrandGradient.brush()),
            contentAlignment = Alignment.Center,
        ) { Icon(Icons.Rounded.Shield, contentDescription = null, tint = WalletColors.Surface, modifier = Modifier.size(18.dp)) }
        Spacer(Modifier.size(10.dp))
        Text("TCC WALLET", style = WalletType.brandWordmark)
        Spacer(Modifier.weight(1f))
        Box(
            Modifier
                .size(34.dp)
                .clip(CircleShape)
                .background(WalletColors.Surface)
                .border(1.dp, WalletColors.Hairline, CircleShape)
                .clickable { },
            contentAlignment = Alignment.Center,
        ) { Icon(Icons.Rounded.PersonOutline, contentDescription = null, tint = WalletColors.Muted, modifier = Modifier.size(18.dp)) }
    }
}

@Composable
private fun EmptyState() {
    Column(
        Modifier.fillMaxWidth().padding(top = 60.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("No credentials yet", style = WalletType.cardTitle)
        Text(
            "Tap Scan to add your first verifiable credential.",
            style = WalletType.bodySmall,
        )
    }
}

private fun countLabel(n: Int): String =
    if (n == 1) "1 verifiable credential" else "$n verifiable credentials"
