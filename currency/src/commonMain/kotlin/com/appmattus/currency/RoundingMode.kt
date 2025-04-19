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

enum class RoundingMode {
    /**
     * Rounding mode to round away from zero. Always increments the digit prior to a non-zero discarded fraction. Note that this rounding mode
     * never decreases the magnitude of the calculated value.
     *
     * Example:
     *
     * | Input Number | Input rounded with [Up] rounding |
     * | :--- | :--- |
     * | 5.5 | 6 |
     * | 2.5 | 3 |
     * | 1.6 | 2 |
     * | 1.1 | 2 |
     * | 1.0 | 1 |
     * | -1.0 | -1 |
     * | -1.1 | -2 |
     * | -1.6 | -2 |
     * | -2.5 | -3 |
     * | -5.5 | -6 |
     */
    Up,

    /**
     * Rounding mode to round towards zero. Never increments the digit prior to a discarded fraction (i.e., truncates). Note that this rounding
     * mode never increases the magnitude of the calculated value. This mode corresponds to the IEEE 754-2019 rounding-direction attribute
     * `roundTowardZero`.
     *
     * Example:
     *
     * | Input Number | Input rounded with [Down] rounding |
     * | :--- | :--- |
     * | 5.5 | 5 |
     * | 2.5 | 2 |
     * | 1.6 | 1 |
     * | 1.1 | 1 |
     * | 1.0 | 1 |
     * | -1.0 | -1 |
     * | -1.1 | -1 |
     * | -1.6 | -1 |
     * | -2.5 | -2 |
     * | -5.5 | -5 |
     */
    Down,

    /**
     * Rounding mode to round towards positive infinity. If the result is positive, behaves as for [Up]; if negative, behaves as for [Down]. Note
     * that this rounding mode never decreases the calculated value. This mode corresponds to the IEEE 754-2019 rounding-direction attribute
     * `roundTowardPositive`.
     *
     * Example:
     *
     * | Input Number | Input rounded with [Ceiling] rounding |
     * | :--- | :--- |
     * | 5.5 | 6 |
     * | 2.5 | 3 |
     * | 1.6 | 2 |
     * | 1.1 | 2 |
     * | 1.0 | 1 |
     * | -1.0 | -1 |
     * | -1.1 | -1 |
     * | -1.6 | -1 |
     * | -2.5 | -2 |
     * | -5.5 | -5 |
     */
    Ceiling,

    /**
     * Rounding mode to round towards negative infinity. If the result is positive, behave as for [Down]; if negative, behave as for [Up]. Note
     * that this rounding mode never increases the calculated value. This mode corresponds to the IEEE 754-2019 rounding-direction attribute
     * `roundTowardNegative`.
     *
     * Example:
     *
     * | Input Number | Input rounded with [Floor] rounding |
     * | :--- | :--- |
     * | 5.5 | 5 |
     * | 2.5 | 2 |
     * | 1.6 | 1 |
     * | 1.1 | 1 |
     * | 1.0 | 1 |
     * | -1.0 | -1 |
     * | -1.1 | -2 |
     * | -1.6 | -2 |
     * | -2.5 | -3 |
     * | -5.5 | -6 |
     */
    Floor,

    /**
     * Rounding mode to round towards "nearest neighbor" unless both neighbors are equidistant, in which case round up. Behaves as for [Up] if
     * the discarded fraction is  0.5; otherwise, behaves as for [Down]. Note that this is the rounding mode commonly taught at school. This mode
     * corresponds to the IEEE 754-2019 rounding-direction attribute `roundTiesToAway`.
     *
     * Example:
     *
     * | Input Number | Input rounded with [HalfUp] rounding |
     * | :--- | :--- |
     * | 5.5 | 6 |
     * | 2.5 | 3 |
     * | 1.6 | 2 |
     * | 1.1 | 1 |
     * | 1.0 | 1 |
     * | -1.0 | -1 |
     * | -1.1 | -1 |
     * | -1.6 | -2 |
     * | -2.5 | -3 |
     * | -5.5 | -6 |
     */
    HalfUp,

    /**
     * Rounding mode to round towards "nearest neighbor" unless both neighbors are equidistant, in which case round down. Behaves as for [Up] if
     * the discarded fraction is > 0.5; otherwise, behaves as for [Down].
     *
     * Example:
     *
     * | Input Number | Input rounded with [HalfDown] rounding |
     * | :--- | :--- |
     * | 5.5 | 5 |
     * | 2.5 | 2 |
     * | 1.6 | 2 |
     * | 1.1 | 1 |
     * | 1.0 | 1 |
     * | -1.0 | -1 |
     * | -1.1 | -1 |
     * | -1.6 | -2 |
     * | -2.5 | -2 |
     * | -5.5 | -5 |
     */
    HalfDown,

    /**
     * Rounding mode to round towards the "nearest neighbor" unless both neighbors are equidistant, in which case, round towards the even
     * neighbor. Behaves as for [HalfUp] if the digit to the left of the discarded fraction is odd; behaves as for [HalfDown] if it's even. Note
     * that this is the rounding mode that statistically minimizes cumulative error when applied repeatedly over a sequence of calculations. It
     * is sometimes known as "Banker's rounding," and is chiefly used in the USA. This rounding mode is analogous to the rounding policy used for
     * `float` and `double` arithmetic in Java. This mode corresponds to the IEEE 754-2019 rounding-direction attribute `roundTiesToEven`.
     *
     * Example:
     *
     * | Input Number | Input rounded with [HalfEven] rounding |
     * | :--- | :--- |
     * | 5.5 | 6 |
     * | 2.5 | 2 |
     * | 1.6 | 2 |
     * | 1.1 | 1 |
     * | 1.0 | 1 |
     * | -1.0 | -1 |
     * | -1.1 | -1 |
     * | -1.6 | -2 |
     * | -2.5 | -2 |
     * | -5.5 | -6 |
     */
    HalfEven
}
