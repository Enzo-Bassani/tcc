package com.tcc.wallet.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val WalletColorScheme = lightColorScheme(
    primary = WalletColors.Brand,
    onPrimary = WalletColors.Surface,
    background = WalletColors.AppBg,
    onBackground = WalletColors.Ink,
    surface = WalletColors.Surface,
    onSurface = WalletColors.Ink,
    error = WalletColors.Brand,
)

private val WalletTypography = Typography().run {
    // Default the whole Material type system to Manrope so any stray Material widget matches.
    copy(
        bodyLarge = bodyLarge.copy(fontFamily = Manrope),
        bodyMedium = bodyMedium.copy(fontFamily = Manrope),
        bodySmall = bodySmall.copy(fontFamily = Manrope),
        labelLarge = labelLarge.copy(fontFamily = Manrope),
        titleMedium = titleMedium.copy(fontFamily = Manrope),
    )
}

@Composable
fun WalletTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = WalletColorScheme,
        typography = WalletTypography,
        content = content,
    )
}
