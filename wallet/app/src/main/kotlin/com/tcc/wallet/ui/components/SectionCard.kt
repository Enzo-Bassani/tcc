package com.tcc.wallet.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.tcc.wallet.ui.model.CredentialField
import com.tcc.wallet.ui.model.CredentialSection
import com.tcc.wallet.ui.theme.WalletColors
import com.tcc.wallet.ui.theme.WalletShapes
import com.tcc.wallet.ui.theme.WalletType

/** One detail section: uppercase header + a white rounded card of field rows. */
@Composable
fun SectionCard(section: CredentialSection) {
    Column(Modifier.fillMaxWidth()) {
        Text(
            section.header.uppercase(),
            style = WalletType.sectionHeader,
            modifier = Modifier.padding(start = 4.dp, end = 4.dp, bottom = 9.dp),
        )
        Column(
            Modifier
                .fillMaxWidth()
                .clip(WalletShapes.field)
                .background(WalletColors.Surface)
                .border(1.dp, WalletColors.Hairline, WalletShapes.field)
                .padding(horizontal = 16.dp),
        ) {
            section.fields.forEachIndexed { i, field ->
                val last = i == section.fields.lastIndex
                if (field.mono) MonoFieldRow(field, last) else NormalFieldRow(field, last)
            }
        }
    }
}

@Composable
private fun NormalFieldRow(field: CredentialField, last: Boolean) {
    Row(
        Modifier
            .fillMaxWidth()
            .bottomDivider(!last)
            .padding(vertical = 13.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(field.label, style = WalletType.fieldLabel)
        Text(
            field.value,
            style = WalletType.fieldValue.copy(color = if (field.good) WalletColors.Success else WalletColors.Ink),
            textAlign = TextAlign.End,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun MonoFieldRow(field: CredentialField, last: Boolean) {
    Column(
        Modifier
            .fillMaxWidth()
            .bottomDivider(!last)
            .padding(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Text(field.label, style = WalletType.fieldLabel)
        Text(
            field.value,
            style = WalletType.monoValue,
            modifier = Modifier
                .fillMaxWidth()
                .clip(WalletShapes.chipSmall)
                .background(WalletColors.MonoChipBg)
                .border(1.dp, WalletColors.Hairline, WalletShapes.chipSmall)
                .padding(horizontal = 11.dp, vertical = 9.dp),
        )
    }
}

/** A 1px divider drawn at the bottom edge (the in-card row separator). */
private fun Modifier.bottomDivider(show: Boolean): Modifier =
    if (!show) this else drawBehind {
        val stroke = 1.dp.toPx()
        drawLine(
            color = WalletColors.Divider,
            start = Offset(0f, size.height - stroke / 2),
            end = Offset(size.width, size.height - stroke / 2),
            strokeWidth = stroke,
        )
    }
