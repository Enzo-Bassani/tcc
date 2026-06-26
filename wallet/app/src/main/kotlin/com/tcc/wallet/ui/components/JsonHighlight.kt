package com.tcc.wallet.ui.components

import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import com.tcc.wallet.ui.theme.WalletColors

/**
 * Syntax-highlight pretty-printed JSON for the Technical view — keys, strings,
 * numbers, keywords and punctuation get the README's color palette. A small
 * hand-rolled tokenizer (the payload is trusted, well-formed JSON from `toString(2)`).
 */
fun highlightJson(pretty: String): AnnotatedString = buildAnnotatedString {
    var i = 0
    val n = pretty.length
    while (i < n) {
        val c = pretty[i]
        when {
            c == '"' -> {
                val end = stringEnd(pretty, i)
                val literal = pretty.substring(i, end)
                val isKey = nextNonSpace(pretty, end) == ':'
                withStyle(SpanStyle(color = if (isKey) WalletColors.JsonKey else WalletColors.JsonString)) {
                    append(literal)
                }
                i = end
            }
            c.isDigit() || (c == '-' && i + 1 < n && pretty[i + 1].isDigit()) -> {
                val start = i
                i++
                while (i < n && (pretty[i].isDigit() || pretty[i] == '.' || pretty[i] == 'e' || pretty[i] == 'E' || pretty[i] == '+' || pretty[i] == '-')) i++
                withStyle(SpanStyle(color = WalletColors.JsonNumber)) { append(pretty.substring(start, i)) }
            }
            pretty.startsWith("true", i) || pretty.startsWith("false", i) || pretty.startsWith("null", i) -> {
                val word = when {
                    pretty.startsWith("true", i) -> "true"
                    pretty.startsWith("false", i) -> "false"
                    else -> "null"
                }
                withStyle(SpanStyle(color = WalletColors.JsonKeyword)) { append(word) }
                i += word.length
            }
            c == '{' || c == '}' || c == '[' || c == ']' || c == ':' || c == ',' -> {
                withStyle(SpanStyle(color = WalletColors.JsonPunct)) { append(c) }
                i++
            }
            else -> {
                append(c)
                i++
            }
        }
    }
}

/** Index just past the closing quote of the string literal starting at [start]. */
private fun stringEnd(s: String, start: Int): Int {
    var i = start + 1
    while (i < s.length) {
        when (s[i]) {
            '\\' -> i += 2
            '"' -> return i + 1
            else -> i++
        }
    }
    return s.length
}

private fun nextNonSpace(s: String, from: Int): Char? {
    var i = from
    while (i < s.length && s[i].isWhitespace()) i++
    return s.getOrNull(i)
}
