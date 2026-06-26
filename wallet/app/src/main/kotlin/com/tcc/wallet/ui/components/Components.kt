package com.tcc.wallet.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.tcc.wallet.ui.theme.BrandGradient
import com.tcc.wallet.ui.theme.Gradient
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletDimens
import com.tcc.wallet.ui.theme.WalletShapes
import com.tcc.wallet.ui.theme.WalletType

/** Full-width gradient primary button (~52dp tall) with the brand colored shadow. */
@Composable
fun PrimaryButton(
    text: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    icon: ImageVector? = null,
    onClick: () -> Unit,
) {
    Box(
        modifier
            .height(WalletDimens.actionButtonHeight)
            .alpha(if (enabled) 1f else 0.45f)
            .shadow(if (enabled) 16.dp else 0.dp, WalletShapes.button, ambientColor = WalletColors.Brand, spotColor = WalletColors.Brand)
            .clip(WalletShapes.button)
            .background(BrandGradient.brush())
            .clickable(enabled = enabled) { onClick() },
        contentAlignment = Alignment.Center,
    ) { ButtonContent(text, icon, WalletColors.Surface) }
}

/** White button with a hairline border (secondary / "outlined" action). */
@Composable
fun OutlinedActionButton(
    text: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    icon: ImageVector? = null,
    textColor: Color = WalletColors.InkSecondary,
    onClick: () -> Unit,
) {
    Box(
        modifier
            .height(WalletDimens.actionButtonHeight)
            .alpha(if (enabled) 1f else 0.45f)
            .clip(WalletShapes.button)
            .background(WalletColors.Surface)
            .border(1.5.dp, WalletColors.SecondaryBorder, WalletShapes.button)
            .clickable(enabled = enabled) { onClick() },
        contentAlignment = Alignment.Center,
    ) { ButtonContent(text, icon, textColor) }
}

/** Dark (ink) filled button — e.g. "View JSON", "Done". */
@Composable
fun DarkButton(
    text: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    icon: ImageVector? = null,
    onClick: () -> Unit,
) {
    Box(
        modifier
            .height(WalletDimens.actionButtonHeight)
            .alpha(if (enabled) 1f else 0.45f)
            .clip(WalletShapes.button)
            .background(WalletColors.Ink)
            .clickable(enabled = enabled) { onClick() },
        contentAlignment = Alignment.Center,
    ) { ButtonContent(text, icon, WalletColors.Surface) }
}

@Composable
private fun ButtonContent(text: String, icon: ImageVector?, color: Color) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.padding(horizontal = 16.dp),
    ) {
        if (icon != null) Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(18.dp))
        Text(text, style = WalletType.buttonLabel.copy(color = color), textAlign = TextAlign.Center)
    }
}

/** A rounded monogram tile (2-letter initials) filled with a credential [accent]. */
@Composable
fun Monogram(
    text: String,
    accent: Gradient,
    modifier: Modifier = Modifier,
    size: androidx.compose.ui.unit.Dp = WalletDimens.monogramHome,
    corner: androidx.compose.ui.unit.Dp = 14.dp,
    fontSize: androidx.compose.ui.unit.TextUnit = androidx.compose.ui.unit.TextUnit.Unspecified,
    contentColor: Color = WalletColors.Surface,
) {
    Box(
        modifier
            .size(size)
            .clip(RoundedCornerShape(corner))
            .background(accent.brush()),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text,
            style = WalletType.cardTitle.copy(
                color = contentColor,
                fontSize = if (fontSize != androidx.compose.ui.unit.TextUnit.Unspecified) fontSize else WalletType.cardTitle.fontSize,
            ),
        )
    }
}

/** Green "Valid" pill: a dot + label. [onDark] tints it for colored hero cards. */
@Composable
fun StatusPill(text: String = "Valid", onDark: Boolean = false) {
    val bg = if (onDark) Color.White.copy(alpha = 0.18f) else WalletColors.SuccessBg
    val ink = if (onDark) WalletColors.Surface else WalletColors.SuccessInk
    val dot = if (onDark) WalletColors.SuccessDot else WalletColors.Success
    Row(
        Modifier
            .clip(WalletShapes.pill)
            .background(bg)
            .padding(horizontal = 9.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Box(Modifier.size(6.dp).clip(CircleShape).background(dot))
        Text(text, style = WalletType.statusPill.copy(color = ink))
    }
}

/** The small indigo verified seal next to issuer/verifier names. */
@Composable
fun VerifiedBadge(size: androidx.compose.ui.unit.Dp = 14.dp, tint: Color = WalletColors.Brand) {
    Icon(Icons.Filled.Verified, contentDescription = "verified", tint = tint, modifier = Modifier.size(size))
}

/** A round 40dp icon button on a faint surface (back / close). */
@Composable
fun CircleIconButton(
    icon: ImageVector,
    contentDescription: String,
    modifier: Modifier = Modifier,
    background: Color = WalletColors.Hairline,
    tint: Color = WalletColors.Ink,
    onClick: () -> Unit,
) {
    Box(
        modifier
            .size(WalletDimens.circleButton)
            .clip(CircleShape)
            .background(background)
            .clickable { onClick() },
        contentAlignment = Alignment.Center,
    ) { Icon(icon, contentDescription = contentDescription, tint = tint, modifier = Modifier.size(20.dp)) }
}

/** Row of one or more action buttons; convenience wrapper. */
@Composable
fun ButtonRow(content: @Composable RowScope.() -> Unit) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(11.dp),
        verticalAlignment = Alignment.CenterVertically,
        content = content,
    )
}

/** Inline labeled value used in offer-preview / consent rows. */
@Composable
fun LabeledValue(label: String, value: String, labelStyle: TextStyle, valueStyle: TextStyle) {
    androidx.compose.foundation.layout.Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(label, style = labelStyle)
        Text(value, style = valueStyle)
    }
}

/** The small green check used in consent attribute rows. */
@Composable
fun CheckMark(tint: Color = WalletColors.Brand, size: androidx.compose.ui.unit.Dp = 18.dp) {
    Icon(Icons.Rounded.Check, contentDescription = null, tint = tint, modifier = Modifier.size(size))
}

/** A bordered monospace multi-line input (the offer/request textarea). */
@Composable
fun MonoTextField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    modifier: Modifier = Modifier,
) {
    androidx.compose.foundation.text.BasicTextField(
        value = value,
        onValueChange = onValueChange,
        textStyle = WalletType.monoField,
        cursorBrush = androidx.compose.ui.graphics.SolidColor(WalletColors.Brand),
        modifier = modifier
            .fillMaxWidth()
            .clip(WalletShapes.input)
            .background(WalletColors.Surface)
            .border(1.dp, WalletColors.FieldBorder, WalletShapes.input)
            .padding(14.dp)
            .heightIn(min = 78.dp),
        decorationBox = { inner ->
            Box {
                if (value.isEmpty()) Text(placeholder, style = WalletType.monoField.copy(color = WalletColors.Faint))
                inner()
            }
        },
    )
}

/** A small indigo text link (e.g. "Choose a different credential"). */
@Composable
fun LinkText(text: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Text(text, style = WalletType.link, modifier = modifier.clickable { onClick() })
}

/** An "or" rule: hairline · or · hairline. */
@Composable
fun OrDivider() {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(Modifier.weight(1f).height(1.dp).background(WalletColors.Hairline))
        Text("or", style = WalletType.bodySmall.copy(color = WalletColors.Faint))
        Box(Modifier.weight(1f).height(1.dp).background(WalletColors.Hairline))
    }
}
