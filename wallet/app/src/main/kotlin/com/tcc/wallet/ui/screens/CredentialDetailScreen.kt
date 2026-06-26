package com.tcc.wallet.ui.screens

import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ChevronLeft
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tcc.wallet.ui.components.DarkButton
import com.tcc.wallet.ui.components.OutlinedActionButton
import com.tcc.wallet.ui.components.SectionCard
import com.tcc.wallet.ui.components.StatusPill
import com.tcc.wallet.ui.components.VerifiedBadge
import com.tcc.wallet.ui.model.CredentialView
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletShapes
import com.tcc.wallet.ui.theme.WalletType

@Composable
fun CredentialDetailScreen(
    credential: CredentialView,
    onBack: () -> Unit,
    onVerify: () -> Unit,
    onViewJson: () -> Unit,
) {
    Box(Modifier.fillMaxSize().background(WalletColors.AppBg)) {
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 120.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            item { Header(onBack) }
            item { HeroCard(credential) }
            items(credential.sections) { section -> SectionCard(section) }
        }

        // Bottom action bar.
        Row(
            Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .background(
                    androidx.compose.ui.graphics.Brush.verticalGradient(
                        listOf(WalletColors.AppBg.copy(alpha = 0f), WalletColors.AppBg),
                    ),
                )
                .padding(start = 20.dp, end = 20.dp, top = 18.dp, bottom = 24.dp),
            horizontalArrangement = Arrangement.spacedBy(11.dp),
        ) {
            OutlinedActionButton(
                "Verify",
                Modifier.weight(1f),
                icon = Icons.Rounded.VerifiedUser,
                onClick = onVerify,
            )
            DarkButton("View JSON", Modifier.weight(1.35f), icon = Icons.Rounded.Code, onClick = onViewJson)
        }
    }
}

@Composable
private fun Header(onBack: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(40.dp).clip(CircleShape).clickable { onBack() },
            contentAlignment = Alignment.Center,
        ) { Icon(Icons.Rounded.ChevronLeft, contentDescription = "Back", tint = WalletColors.Ink, modifier = Modifier.size(26.dp)) }
        Spacer(Modifier.size(4.dp))
        Text("Credential", style = WalletType.headerTitle)
    }
}

@Composable
private fun HeroCard(credential: CredentialView) {
    Box(
        Modifier
            .fillMaxWidth()
            .shadow(22.dp, WalletShapes.hero, ambientColor = Color(0x42282850), spotColor = Color(0x42282850))
            .clip(WalletShapes.hero)
            .background(credential.accent.brush()),
    ) {
        // Decorative bleeding circles.
        Box(Modifier.size(150.dp).align(Alignment.TopEnd).offset(x = 55.dp, y = (-55).dp).clip(CircleShape).background(Color.White.copy(alpha = 0.10f)))
        Box(Modifier.size(120.dp).align(Alignment.BottomStart).offset(x = (-40).dp, y = 40.dp).clip(CircleShape).background(Color.White.copy(alpha = 0.07f)))

        Column(Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(Color.White.copy(alpha = 0.20f)),
                    contentAlignment = Alignment.Center,
                ) { Text(credential.monogram, style = WalletType.cardTitle.copy(color = Color.White)) }
                Spacer(Modifier.weight(1f))
                StatusPill(credential.statusLabel, onDark = true)
            }
            Text(credential.typeName, style = WalletType.heroTitle.copy(color = Color.White))
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                VerifiedBadge(14.dp, tint = Color.White)
                Text(credential.issuerName, style = WalletType.cardIssuer.copy(color = Color.White.copy(alpha = 0.95f), fontSize = 13.5.sp))
            }
            if (credential.holderName.isNotBlank()) {
                Column(Modifier.padding(top = 6.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text("ISSUED TO", style = WalletType.cardIssuer.copy(color = Color.White.copy(alpha = 0.78f), letterSpacing = 0.3.sp))
                    Text(credential.holderName, style = WalletType.heroHolder.copy(color = Color.White))
                }
            }
        }
    }
}
