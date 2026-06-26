package com.tcc.wallet.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tcc.wallet.ui.theme.Gradient
import com.tcc.wallet.ui.theme.VerifierAccent
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletShapes
import com.tcc.wallet.ui.theme.WalletType

/**
 * A bottom sheet over a dimmed scrim. Slides up and fades the scrim in on first
 * composition (README `sheetUp` 0.34s). [content] is laid out in the sheet column —
 * its own scroll/padding is the caller's responsibility.
 */
@Composable
fun SheetOverlay(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    dark: Boolean = false,
    heightFraction: Float? = null,
    shape: Shape = if (dark) WalletShapes.jsonSheet else WalletShapes.sheet,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    var shown by remember { mutableStateOf(false) }
    androidx.compose.runtime.LaunchedEffect(Unit) { shown = true }
    val progress by animateFloatAsState(
        targetValue = if (shown) 1f else 0f,
        animationSpec = tween(340),
        label = "sheet",
    )

    Box(Modifier.fillMaxSize()) {
        Box(
            Modifier
                .fillMaxSize()
                .background(WalletColors.ScrimDark.copy(alpha = 0.46f * progress))
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                ) { onDismiss() },
        )
        Column(
            modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .then(if (heightFraction != null) Modifier.fillMaxHeight(heightFraction) else Modifier)
                .graphicsLayer { translationY = size.height * (1f - progress) }
                .clip(shape)
                .background(if (dark) WalletColors.JsonBg else WalletColors.Surface)
                // Block click-through to the scrim.
                .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) {},
        ) {
            Grabber(dark)
            content()
        }
    }
}

@Composable
private fun Grabber(dark: Boolean) {
    Box(Modifier.fillMaxWidth().padding(top = 10.dp), contentAlignment = Alignment.Center) {
        Box(
            Modifier
                .size(width = 40.dp, height = 4.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(if (dark) Color.White.copy(alpha = 0.18f) else WalletColors.SecondaryBorder),
        )
    }
}

/** Sheet header: an indigo (or dark) icon chip + title + mono protocol sublabel + close. */
@Composable
fun SheetHeader(
    icon: ImageVector,
    title: String,
    protocol: String,
    onClose: () -> Unit,
    dark: Boolean = false,
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier.size(36.dp).clip(WalletShapes.chip).background(WalletColors.BrandTint),
            contentAlignment = Alignment.Center,
        ) { Icon(icon, contentDescription = null, tint = WalletColors.Brand, modifier = Modifier.size(20.dp)) }
        Column(Modifier.weight(1f)) {
            Text(title, style = WalletType.cardTitle.copy(color = if (dark) Color.White else WalletColors.Ink))
            Text(protocol, style = if (dark) WalletType.jsonSubtitle else WalletType.protocolLabel)
        }
        CircleIconButton(
            Icons.Rounded.Close,
            contentDescription = "Close",
            background = if (dark) Color.White.copy(alpha = 0.10f) else WalletColors.Hairline,
            tint = if (dark) Color.White else WalletColors.Ink,
            onClick = onClose,
        )
    }
}

/** The verifier identity card shown in the present flow. */
@Composable
fun VerifierCard(name: String, domain: String, monogram: String, accent: Gradient = VerifierAccent) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(WalletShapes.input)
            .background(WalletColors.Surface)
            .border(1.dp, WalletColors.Hairline, WalletShapes.input)
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Monogram(monogram, accent, size = 42.dp, corner = 11.dp, fontSize = 13.sp)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(name, style = WalletType.cardTitle.copy(fontSize = 15.sp))
            Text(
                "$domain · verified",
                style = WalletType.cardIssuer.copy(fontFamily = WalletType.monoValue.fontFamily, color = WalletColors.Faint),
            )
        }
        VerifiedBadge(20.dp)
    }
}

/** The success terminal step (green pop-in check + title + body). The "Done" button
 *  is supplied by the caller. */
@Composable
fun SuccessStep(title: String, body: String) {
    var popped by remember { mutableStateOf(false) }
    androidx.compose.runtime.LaunchedEffect(Unit) { popped = true }
    val scale by animateFloatAsState(if (popped) 1f else 0.5f, tween(450), label = "pop")

    Column(
        Modifier.fillMaxWidth().padding(vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(
            Modifier
                .size(72.dp)
                .graphicsLayer { scaleX = scale; scaleY = scale; alpha = if (popped) 1f else 0f }
                .clip(CircleShape)
                .background(WalletColors.SuccessBg),
            contentAlignment = Alignment.Center,
        ) { Icon(Icons.Rounded.Check, contentDescription = null, tint = WalletColors.Success, modifier = Modifier.size(36.dp)) }
        Text(title, style = WalletType.success)
        Text(body, style = WalletType.bodySmall, textAlign = TextAlign.Center)
    }
}
