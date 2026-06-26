package com.tcc.wallet.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.unit.dp
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletShapes
import com.tcc.wallet.ui.theme.WalletType

/** A dark toast pill, centered near the bottom; slides up + fades in. Auto-dismissal
 *  is the caller's job (a 2400ms timer in the root). */
@Composable
fun Toast(message: String) {
    var shown by remember { mutableStateOf(false) }
    androidx.compose.runtime.LaunchedEffect(Unit) { shown = true }
    val progress by animateFloatAsState(if (shown) 1f else 0f, tween(250), label = "toast")

    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
        Row(
            Modifier
                .padding(bottom = 90.dp)
                .graphicsLayer { translationY = 14.dp.toPx() * (1f - progress); alpha = progress }
                .shadow(18.dp, WalletShapes.chip)
                .clip(WalletShapes.chip)
                .background(WalletColors.Ink)
                .padding(horizontal = 18.dp, vertical = 13.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                Icons.Rounded.CheckCircle,
                contentDescription = null,
                tint = WalletColors.SuccessDot,
                modifier = Modifier.size(16.dp),
            )
            Text(message, style = WalletType.toast)
        }
    }
}
