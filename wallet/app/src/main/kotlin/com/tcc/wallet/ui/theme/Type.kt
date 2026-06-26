package com.tcc.wallet.ui.theme

import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.tcc.wallet.R

/** Manrope as a single variable font (`wght` axis); one [Font] per design weight so
 *  Compose's matcher resolves 400/500/600/700/800 to the right axis instance. */
private fun manrope(weight: Int) = Font(R.font.manrope, weight = FontWeight(weight))

val Manrope = FontFamily(
    manrope(400),
    manrope(500),
    manrope(600),
    manrope(700),
    manrope(800),
)

/** JetBrains Mono (static instances) — protocol labels, URIs, key material, JSON. */
val JetBrainsMono = FontFamily(
    Font(R.font.jetbrains_mono_regular, FontWeight.Normal),
    Font(R.font.jetbrains_mono_medium, FontWeight.Medium),
    Font(R.font.jetbrains_mono_bold, FontWeight.Bold),
)

private val W500 = FontWeight(500)
private val W600 = FontWeight(600)
private val W700 = FontWeight(700)
private val W800 = FontWeight(800)

/** Named text styles mirroring the handoff type scale (px → sp). */
object WalletType {
    val brandWordmark = TextStyle(fontFamily = Manrope, fontWeight = W800, fontSize = 13.sp, letterSpacing = 0.7.sp, color = WalletColors.Muted)
    val screenTitle = TextStyle(fontFamily = Manrope, fontWeight = W800, fontSize = 28.sp, letterSpacing = (-0.6).sp, color = WalletColors.Ink)
    val screenSubtitle = TextStyle(fontFamily = Manrope, fontWeight = W600, fontSize = 14.5.sp, color = WalletColors.Muted)

    val cardTitle = TextStyle(fontFamily = Manrope, fontWeight = W800, fontSize = 16.sp, color = WalletColors.Ink)
    val cardIssuer = TextStyle(fontFamily = Manrope, fontWeight = W600, fontSize = 12.5.sp, color = WalletColors.Muted)
    val cardHolder = TextStyle(fontFamily = Manrope, fontWeight = W600, fontSize = 13.sp, color = WalletColors.Faint)

    val heroTitle = TextStyle(fontFamily = Manrope, fontWeight = W800, fontSize = 22.sp, letterSpacing = (-0.4).sp)
    val heroHolder = TextStyle(fontFamily = Manrope, fontWeight = W800, fontSize = 17.sp)

    val sectionHeader = TextStyle(fontFamily = Manrope, fontWeight = W800, fontSize = 11.5.sp, letterSpacing = 0.6.sp, color = WalletColors.Faint)
    val fieldLabel = TextStyle(fontFamily = Manrope, fontWeight = W500, fontSize = 13.5.sp, color = WalletColors.Muted)
    val fieldValue = TextStyle(fontFamily = Manrope, fontWeight = W700, fontSize = 14.sp, color = WalletColors.Ink)

    val headerTitle = TextStyle(fontFamily = Manrope, fontWeight = W700, fontSize = 16.sp, color = WalletColors.Ink)
    val buttonLabel = TextStyle(fontFamily = Manrope, fontWeight = W700, fontSize = 15.sp)
    val detailButtonLabel = TextStyle(fontFamily = Manrope, fontWeight = W700, fontSize = 14.5.sp)

    val statusPill = TextStyle(fontFamily = Manrope, fontWeight = W700, fontSize = 11.sp)

    val body = TextStyle(fontFamily = Manrope, fontWeight = W500, fontSize = 14.sp, color = WalletColors.Muted)
    val bodySmall = TextStyle(fontFamily = Manrope, fontWeight = W500, fontSize = 13.5.sp, color = WalletColors.Muted)
    val success = TextStyle(fontFamily = Manrope, fontWeight = W800, fontSize = 20.sp, color = WalletColors.Ink)

    val inputLabel = TextStyle(fontFamily = Manrope, fontWeight = W800, fontSize = 11.5.sp, letterSpacing = 0.5.sp, color = WalletColors.Faint)
    val link = TextStyle(fontFamily = Manrope, fontWeight = W700, fontSize = 13.sp, color = WalletColors.Brand)
    val toast = TextStyle(fontFamily = Manrope, fontWeight = W600, fontSize = 13.5.sp, color = WalletColors.Surface)

    // Monospace
    val protocolLabel = TextStyle(fontFamily = JetBrainsMono, fontWeight = W700, fontSize = 11.sp, letterSpacing = 0.5.sp, color = WalletColors.Faint)
    val monoValue = TextStyle(fontFamily = JetBrainsMono, fontWeight = FontWeight.Normal, fontSize = 11.5.sp, color = WalletColors.InkSecondary, lineHeight = 17.sp)
    val monoField = TextStyle(fontFamily = JetBrainsMono, fontWeight = FontWeight.Normal, fontSize = 12.5.sp, color = WalletColors.Ink, lineHeight = 19.sp)
    val json = TextStyle(fontFamily = JetBrainsMono, fontWeight = FontWeight.Normal, fontSize = 12.sp, lineHeight = 20.sp)
    val jsonSubtitle = TextStyle(fontFamily = JetBrainsMono, fontWeight = FontWeight.Normal, fontSize = 11.5.sp, color = WalletColors.JsonSubtitle)
}
