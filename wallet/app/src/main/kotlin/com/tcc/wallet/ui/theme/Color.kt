package com.tcc.wallet.ui.theme

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

/** The wallet's color tokens. */
object WalletColors {
    val Ink = Color(0xFF181B2A) // headlines, primary values, dark buttons
    val InkSecondary = Color(0xFF3A4055) // secondary button text
    val Muted = Color(0xFF6B7390) // subtitles, field labels
    val Faint = Color(0xFF9AA1B9) // captions, section headers, placeholders
    val Chevron = Color(0xFFC4C9DB) // list chevrons

    val AppBg = Color(0xFFF5F6FB) // screen background
    val Surface = Color(0xFFFFFFFF) // cards, sheets, fields
    val Hairline = Color(0xFFECEDF4) // card borders
    val FieldBorder = Color(0xFFE2E4EE) // inputs
    val SecondaryBorder = Color(0xFFDADCE8) // secondary buttons
    val Divider = Color(0xFFF1F2F8) // in-card row separators
    val MonoChipBg = Color(0xFFF6F7FB) // monospace value chip bg

    val Brand = Color(0xFF4F46E5) // primary accent / selected state
    val Brand2 = Color(0xFF6366F1) // gradient end
    val BrandTint = Color(0xFFEEF0FE) // icon chip bg
    val SelectedBg = Color(0xFFF4F4FE) // selected card bg

    val Success = Color(0xFF15A06B) // valid status, checks
    val SuccessBg = Color(0xFFE6F6EF) // success circle / status pills
    val SuccessInk = Color(0xFF0E7A53) // status pill text
    val SuccessDot = Color(0xFF34D399) // status dot on colored cards / toast check

    val ScannerDark = Color(0xFF0B0D12) // scanner background
    val JsonBg = Color(0xFF0F1320) // technical (JSON) view background
    val JsonSubtitle = Color(0xFF8B93A7)

    // JSON syntax highlighting (on JsonBg)
    val JsonKey = Color(0xFF93C5FD)
    val JsonString = Color(0xFF86EFAC)
    val JsonNumber = Color(0xFFFBBF24)
    val JsonKeyword = Color(0xFFF0ABFC)
    val JsonPunct = Color(0xFF7E879B)

    val ScrimDark = Color(0x75_0C0E14) // ~rgba(12,14,20,.46) overlay behind sheets
}

/**
 * A two-stop accent gradient. `135deg` in the design ≈ top-left → bottom-right, which
 * `Offset.Zero → Offset.Infinite` resolves to over the drawn bounds.
 */
data class Gradient(val start: Color, val end: Color) {
    fun brush(): Brush = Brush.linearGradient(
        colors = listOf(start, end),
        start = Offset.Zero,
        end = Offset.Infinite,
    )
}

val BrandGradient = Gradient(WalletColors.Brand, WalletColors.Brand2)
val DiplomaAccent = Gradient(Color(0xFF4F46E5), Color(0xFF6366F1))
val StudentAccent = Gradient(Color(0xFF334155), Color(0xFF475569))
val EnrollAccent = Gradient(Color(0xFF0F766E), Color(0xFF14919B))
val VerifierAccent = StudentAccent // gov.br "GB" monogram (slate)
