package com.tcc.wallet.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.dp

/** Spacing, radii and shadow tokens (README "Spacing, radius, shadow"). */
object WalletDimens {
    val screenPadding = 20.dp
    val cardPadding = 16.dp
    val heroPadding = 22.dp

    val radiusCard = 20.dp
    val radiusHero = 24.dp
    val radiusField = 18.dp
    val radiusInput = 16.dp
    val radiusButton = 16.dp
    val radiusDetailButton = 15.dp
    val radiusChipSmall = 10.dp
    val radiusChip = 12.dp
    val radiusSheet = 26.dp
    val radiusJsonSheet = 24.dp
    val radiusPill = 20.dp

    val monogramHome = 50.dp
    val monogramHero = 48.dp
    val monogramSmall = 42.dp

    val actionButtonHeight = 52.dp
    val circleButton = 40.dp
}

object WalletShapes {
    val card = RoundedCornerShape(WalletDimens.radiusCard)
    val hero = RoundedCornerShape(WalletDimens.radiusHero)
    val field = RoundedCornerShape(WalletDimens.radiusField)
    val input = RoundedCornerShape(WalletDimens.radiusInput)
    val button = RoundedCornerShape(WalletDimens.radiusButton)
    val detailButton = RoundedCornerShape(WalletDimens.radiusDetailButton)
    val chipSmall = RoundedCornerShape(WalletDimens.radiusChipSmall)
    val chip = RoundedCornerShape(WalletDimens.radiusChip)
    val pill = RoundedCornerShape(WalletDimens.radiusPill)
    val sheet = RoundedCornerShape(topStart = WalletDimens.radiusSheet, topEnd = WalletDimens.radiusSheet)
    val jsonSheet = RoundedCornerShape(topStart = WalletDimens.radiusJsonSheet, topEnd = WalletDimens.radiusJsonSheet)
}
