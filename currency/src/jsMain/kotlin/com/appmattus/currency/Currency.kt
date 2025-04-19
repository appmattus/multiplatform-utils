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

actual object Currency {

    actual fun format(amount: Double, currencyCode: String, locale: String, showFractionDigits: Boolean, roundingMode: RoundingMode): String {
        val formatter = Intl.NumberFormat(
            locale,
            numberFormatOptions {
                style = "currency"
                currency = currencyCode

                this.roundingMode = when (roundingMode) {
                    RoundingMode.Up -> "expand"
                    RoundingMode.Down -> "trunc"
                    RoundingMode.Ceiling -> "ceil"
                    RoundingMode.Floor -> "floor"
                    RoundingMode.HalfUp -> "halfExpand"
                    RoundingMode.HalfDown -> "halfTrunc"
                    RoundingMode.HalfEven -> "halfEven"
                }

                if (!showFractionDigits) {
                    minimumFractionDigits = 0
                    maximumFractionDigits = 0
                }
            }
        )

        return formatter.format(amount)
    }
}

private fun numberFormatOptions(builder: NumberFormatOptions.() -> Unit): NumberFormatOptions {
    val options = js("{}").unsafeCast<NumberFormatOptions>()
    builder(options)
    return options
}

private external class Intl {
    class NumberFormat(locale: String = definedExternally, options: NumberFormatOptions = definedExternally) {
        fun format(value: Double): String
    }
}

private external interface NumberFormatOptions {
    var style: String?
    var currency: String?
    var roundingMode: String?
    var minimumFractionDigits: Int?
    var maximumFractionDigits: Int?
}
