package com.tcc.wallet.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tcc.wallet.ui.model.CredentialView
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletDimens
import com.tcc.wallet.ui.theme.WalletShapes
import com.tcc.wallet.ui.theme.WalletType

/** A tappable home-list credential card (monogram · type/issuer/holder · status + chevron). */
@Composable
fun CredentialCard(view: CredentialView, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .shadow(6.dp, WalletShapes.card, ambientColor = Color(0x14181B2A), spotColor = Color(0x14181B2A))
            .clip(WalletShapes.card)
            .background(WalletColors.Surface)
            .border(1.dp, WalletColors.Hairline, WalletShapes.card)
            .clickable { onClick() }
            .padding(WalletDimens.cardPadding),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Monogram(view.monogram, view.accent, size = WalletDimens.monogramHome, corner = 14.dp, fontSize = 15.sp)

        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(view.typeName, style = WalletType.cardTitle, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    view.issuerName,
                    style = WalletType.cardIssuer,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                VerifiedBadge(13.dp)
            }
            if (view.holderName.isNotBlank()) {
                Text(view.holderName, style = WalletType.cardHolder, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }

        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(6.dp)) {
            StatusPill(view.statusLabel)
            Icon(
                Icons.Rounded.ChevronRight,
                contentDescription = null,
                tint = WalletColors.Chevron,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}
