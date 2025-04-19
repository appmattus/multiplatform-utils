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

expect object Currency {

    /**
     * Format a currency [amount] taking [locale] into account. Decimals are shown based on [showFractionDigits] and numbers are rounded based
     * on [roundingMode].
     * @param amount Currency amount to format
     * @param currencyCode ISO-4217 alphabetic currency code, i.e. CAD
     * @param locale IETF BCP 47 language tag, i.e. en-CA
     * @param showFractionDigits `true` to show fraction digits, `false` otherwise
     * @param roundingMode [RoundingMode] to use
     */
    fun format(
        amount: Double,
        currencyCode: String,
        locale: String,
        showFractionDigits: Boolean = true,
        roundingMode: RoundingMode = RoundingMode.HalfEven
    ): String
}
