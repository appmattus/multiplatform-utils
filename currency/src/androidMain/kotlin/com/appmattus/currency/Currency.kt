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

import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

actual object Currency {
    actual fun format(
        amount: Double,
        currencyCode: String,
        locale: String,
        showFractionDigits: Boolean,
        roundingMode: RoundingMode
    ): String {
        return NumberFormat.getCurrencyInstance(Locale.forLanguageTag(locale)).apply {
            val currency = Currency.getInstance(currencyCode)
            this.currency = currency
            this.roundingMode = when (roundingMode) {
                RoundingMode.Up -> java.math.RoundingMode.UP
                RoundingMode.Down -> java.math.RoundingMode.DOWN
                RoundingMode.Ceiling -> java.math.RoundingMode.CEILING
                RoundingMode.Floor -> java.math.RoundingMode.FLOOR
                RoundingMode.HalfUp -> java.math.RoundingMode.HALF_UP
                RoundingMode.HalfDown -> java.math.RoundingMode.HALF_DOWN
                RoundingMode.HalfEven -> java.math.RoundingMode.HALF_EVEN
            }

            // When showing decimal places use value from currency as NumberFormat defaults to device locale
            // TND is formatted with 2 dp and not 3 dp and JPY with 2 dp and not 0 dp
            (if (!showFractionDigits) 0 else currency.defaultFractionDigits).let { decimalPlaces ->
                minimumFractionDigits = decimalPlaces
                maximumFractionDigits = decimalPlaces
            }
        }.format(amount)
    }
}
