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

import platform.Foundation.NSLocale
import platform.Foundation.NSNumber
import platform.Foundation.NSNumberFormatter
import platform.Foundation.NSNumberFormatterCurrencyStyle
import platform.Foundation.NSNumberFormatterRoundCeiling
import platform.Foundation.NSNumberFormatterRoundDown
import platform.Foundation.NSNumberFormatterRoundFloor
import platform.Foundation.NSNumberFormatterRoundHalfDown
import platform.Foundation.NSNumberFormatterRoundHalfEven
import platform.Foundation.NSNumberFormatterRoundHalfUp
import platform.Foundation.NSNumberFormatterRoundUp

actual object Currency {

    actual fun format(amount: Double, currencyCode: String, locale: String, showFractionDigits: Boolean, roundingMode: RoundingMode): String {
        val formatter = NSNumberFormatter()
        formatter.numberStyle = NSNumberFormatterCurrencyStyle
        formatter.locale = NSLocale(localeIdentifier = locale)
        formatter.currencyCode = currencyCode
        formatter.roundingMode = when (roundingMode) {
            RoundingMode.Up -> NSNumberFormatterRoundUp
            RoundingMode.Down -> NSNumberFormatterRoundDown
            RoundingMode.Ceiling -> NSNumberFormatterRoundCeiling
            RoundingMode.Floor -> NSNumberFormatterRoundFloor
            RoundingMode.HalfUp -> NSNumberFormatterRoundHalfUp
            RoundingMode.HalfDown -> NSNumberFormatterRoundHalfDown
            RoundingMode.HalfEven -> NSNumberFormatterRoundHalfEven
        }
        if (!showFractionDigits) {
            formatter.minimumFractionDigits = 0uL
            formatter.maximumFractionDigits = 0uL
        }
        return formatter.stringFromNumber(NSNumber(double = amount)).orEmpty()
    }
}
