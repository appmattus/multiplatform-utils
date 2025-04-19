/*
 * Copyright 2025 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appmattus.currency

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class CurrencyTest : RobolectricTest() {

    @Test
    fun testEnGb() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "en-GB")
        }
        assertContentEquals(listOf("£1,345.23", "€1,345.23", "US$1,345.23", "CA$1,345.23", "MX$1,345.23", "JP¥1,345"), actual)
    }

    @Test
    fun testEnGbWithoutDecimals() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "en-GB", showFractionDigits = false)
        }

        assertContentEquals(listOf("£1,345", "€1,345", "US$1,345", "CA$1,345", "MX$1,345", "JP¥1,345"), actual)
    }

    @Test
    fun testEnUs() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "en-US")
        }

        assertContentEquals(listOf("£1,345.23", "€1,345.23", "$1,345.23", "CA$1,345.23", "MX$1,345.23", "¥1,345"), actual)
    }

    @Test
    fun testEnUsWithoutDecimals() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "en-US", showFractionDigits = false)
        }

        assertContentEquals(listOf("£1,345", "€1,345", "$1,345", "CA$1,345", "MX$1,345", "¥1,345"), actual)
    }

    @Test
    fun testEnCa() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "en-CA")
        }

        assertContentEquals(listOf("£1,345.23", "€1,345.23", "US$1,345.23", "$1,345.23", "MX$1,345.23", "JP¥1,345"), actual)
    }

    @Test
    fun testEnCaWithoutDecimals() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "en-CA", showFractionDigits = false)
        }

        assertContentEquals(listOf("£1,345", "€1,345", "US$1,345", "$1,345", "MX$1,345", "JP¥1,345"), actual)
    }

    @Test
    fun testFrCa() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "fr-CA")
        }

        assertContentEquals(listOf("1 345,23 £", "1 345,23 €", "1 345,23 $ US", "1 345,23 $", "1 345,23 MXN", "1 345 ¥"), actual)
    }

    @Test
    fun testFrCaWithoutDecimals() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "fr-CA", showFractionDigits = false)
        }

        assertContentEquals(listOf("1 345 £", "1 345 €", "1 345 $ US", "1 345 $", "1 345 MXN", "1 345 ¥"), actual)
    }

    @Test
    fun testDeDe() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "de-DE")
        }

        assertContentEquals(listOf("1.345,23 £", "1.345,23 €", "1.345,23 $", "1.345,23 CA$", "1.345,23 MX\$", "1.345 ¥"), actual)
    }

    @Test
    fun testDeDeWithoutDecimals() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "de-DE", showFractionDigits = false)
        }

        assertContentEquals(listOf("1.345 £", "1.345 €", "1.345 $", "1.345 CA$", "1.345 MX\$", "1.345 ¥"), actual)
    }

    @Test
    fun testFrFr() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "fr-FR").replace(" ", " ")
        }

        assertContentEquals(listOf("1 345,23 £GB", "1 345,23 €", "1 345,23 \$US", "1 345,23 \$CA", "1 345,23 \$MX", "1 345 JPY"), actual)
    }

    @Test
    fun testFrFrWithoutDecimals() {
        val actual = listOf("GBP", "EUR", "USD", "CAD", "MXN", "JPY").map { currencyCode ->
            Currency.format(amount = 1345.23, currencyCode = currencyCode, locale = "fr-FR", showFractionDigits = false).replace(" ", " ")
        }

        assertContentEquals(listOf("1 345 £GB", "1 345 €", "1 345 \$US", "1 345 \$CA", "1 345 \$MX", "1 345 JPY"), actual)
    }

    @Test
    fun testTnd() {
        val actual = listOf("en-GB", "en-US", "en-CA", "fr-CA", "de-DE", "fr-FR").map { locale ->
            Currency.format(amount = 1345.23, currencyCode = "TND", locale = locale).replace("TND ", "TND").replace(" ", " ")
        }

        assertContentEquals(listOf("TND1,345.230", "TND1,345.230", "TND1,345.230", "1 345,230 TND", "1.345,230 TND", "1 345,230 TND"), actual)
    }

    @Test
    fun testTndWithoutDecimals() {
        val actual = listOf("en-GB", "en-US", "en-CA", "fr-CA", "de-DE", "fr-FR").map { locale ->
            Currency.format(amount = 1345.23, currencyCode = "TND", locale = locale, showFractionDigits = false)
                .replace("TND ", "TND")
                .replace(" ", " ")
        }

        assertContentEquals(listOf("TND1,345", "TND1,345", "TND1,345", "1 345 TND", "1.345 TND", "1 345 TND"), actual)
    }

    @Test
    fun testRoundingModeUp() {
        mapOf(
            5.5 to 6,
            2.5 to 3,
            1.6 to 2,
            1.1 to 2,
            1.0 to 1,
            -1.0 to -1,
            -1.1 to -2,
            -1.6 to -2,
            -2.5 to -3,
            -5.5 to -6
        ).forEach { (value, expected) ->
            val actual = Currency.format(value, "JPY", "en-US", roundingMode = RoundingMode.Up)
            assertEquals(expected.toString(), actual.replace("¥", ""))
        }
    }

    @Test
    fun testRoundingModeDown() {
        mapOf(
            5.5 to 5,
            2.5 to 2,
            1.6 to 1,
            1.1 to 1,
            1.0 to 1,
            -1.0 to -1,
            -1.1 to -1,
            -1.6 to -1,
            -2.5 to -2,
            -5.5 to -5
        ).forEach { (value, expected) ->
            val actual = Currency.format(value, "JPY", "en-US", roundingMode = RoundingMode.Down)
            assertEquals(expected.toString(), actual.replace("¥", ""))
        }
    }

    @Test
    fun testRoundingModeCeiling() {
        mapOf(
            5.5 to 6,
            2.5 to 3,
            1.6 to 2,
            1.1 to 2,
            1.0 to 1,
            -1.0 to -1,
            -1.1 to -1,
            -1.6 to -1,
            -2.5 to -2,
            -5.5 to -5
        ).forEach { (value, expected) ->
            val actual = Currency.format(value, "JPY", "en-US", roundingMode = RoundingMode.Ceiling)
            assertEquals(expected.toString(), actual.replace("¥", ""))
        }
    }

    @Test
    fun testRoundingModeFloor() {
        mapOf(
            5.5 to 5,
            2.5 to 2,
            1.6 to 1,
            1.1 to 1,
            1.0 to 1,
            -1.0 to -1,
            -1.1 to -2,
            -1.6 to -2,
            -2.5 to -3,
            -5.5 to -6
        ).forEach { (value, expected) ->
            val actual = Currency.format(value, "JPY", "en-US", roundingMode = RoundingMode.Floor)
            assertEquals(expected.toString(), actual.replace("¥", ""))
        }
    }

    @Test
    fun testRoundingModeHalfUp() {
        mapOf(
            5.5 to 6,
            2.5 to 3,
            1.6 to 2,
            1.1 to 1,
            1.0 to 1,
            -1.0 to -1,
            -1.1 to -1,
            -1.6 to -2,
            -2.5 to -3,
            -5.5 to -6
        ).forEach { (value, expected) ->
            val actual = Currency.format(value, "JPY", "en-US", roundingMode = RoundingMode.HalfUp)
            assertEquals(expected.toString(), actual.replace("¥", ""))
        }
    }

    @Test
    fun testRoundingModeHalfDown() {
        mapOf(
            5.5 to 5,
            2.5 to 2,
            1.6 to 2,
            1.1 to 1,
            1.0 to 1,
            -1.0 to -1,
            -1.1 to -1,
            -1.6 to -2,
            -2.5 to -2,
            -5.5 to -5
        ).forEach { (value, expected) ->
            val actual = Currency.format(value, "JPY", "en-US", roundingMode = RoundingMode.HalfDown)
            assertEquals(expected.toString(), actual.replace("¥", ""))
        }
    }

    @Test
    fun testRoundingModeHalfEven() {
        mapOf(
            5.5 to 6,
            2.5 to 2,
            1.6 to 2,
            1.1 to 1,
            1.0 to 1,
            -1.0 to -1,
            -1.1 to -1,
            -1.6 to -2,
            -2.5 to -2,
            -5.5 to -6
        ).forEach { (value, expected) ->
            val actual = Currency.format(value, "JPY", "en-US", roundingMode = RoundingMode.HalfEven)
            assertEquals(expected.toString(), actual.replace("¥", ""))
        }
    }
}
