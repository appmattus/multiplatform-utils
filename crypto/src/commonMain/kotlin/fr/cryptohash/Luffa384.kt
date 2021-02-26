// $Id: Luffa384.java 235 2010-06-18 15:31:36Z tp $
package fr.cryptohash

/**
 *
 * This class implements Luffa-384 digest algorithm under the
 * [Digest] API.
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
</pre> *
 *
 * @version   $Revision: 235 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Luffa384 : DigestEngine() {
    private var V00 = 0
    private var V01 = 0
    private var V02 = 0
    private var V03 = 0
    private var V04 = 0
    private var V05 = 0
    private var V06 = 0
    private var V07 = 0
    private var V10 = 0
    private var V11 = 0
    private var V12 = 0
    private var V13 = 0
    private var V14 = 0
    private var V15 = 0
    private var V16 = 0
    private var V17 = 0
    private var V20 = 0
    private var V21 = 0
    private var V22 = 0
    private var V23 = 0
    private var V24 = 0
    private var V25 = 0
    private var V26 = 0
    private var V27 = 0
    private var V30 = 0
    private var V31 = 0
    private var V32 = 0
    private var V33 = 0
    private var V34 = 0
    private var V35 = 0
    private var V36 = 0
    private var V37 = 0
    private lateinit var tmpBuf: ByteArray

    /*
	 * Private communication for Luffa designer Watanabe Dai:
	 *
	 * << I think that there is no problem to use the same
	 *    setting as CubeHash, namely B = 256*ceil(k / 256). >>
	 */
    override val blockLength: Int
        get() = 32

    override val digestLength: Int
        get() = 48

    override fun copy(): Digest {
        return copyState(Luffa384())
    }

    private fun copyState(dst: Luffa384): Digest {
        dst.V00 = V00
        dst.V01 = V01
        dst.V02 = V02
        dst.V03 = V03
        dst.V04 = V04
        dst.V05 = V05
        dst.V06 = V06
        dst.V07 = V07
        dst.V10 = V10
        dst.V11 = V11
        dst.V12 = V12
        dst.V13 = V13
        dst.V14 = V14
        dst.V15 = V15
        dst.V16 = V16
        dst.V17 = V17
        dst.V20 = V20
        dst.V21 = V21
        dst.V22 = V22
        dst.V23 = V23
        dst.V24 = V24
        dst.V25 = V25
        dst.V26 = V26
        dst.V27 = V27
        dst.V30 = V30
        dst.V31 = V31
        dst.V32 = V32
        dst.V33 = V33
        dst.V34 = V34
        dst.V35 = V35
        dst.V36 = V36
        dst.V37 = V37
        return super.copyState(dst)
    }

    override fun engineReset() {
        V00 = IV[0]
        V01 = IV[1]
        V02 = IV[2]
        V03 = IV[3]
        V04 = IV[4]
        V05 = IV[5]
        V06 = IV[6]
        V07 = IV[7]
        V10 = IV[8]
        V11 = IV[9]
        V12 = IV[10]
        V13 = IV[11]
        V14 = IV[12]
        V15 = IV[13]
        V16 = IV[14]
        V17 = IV[15]
        V20 = IV[16]
        V21 = IV[17]
        V22 = IV[18]
        V23 = IV[19]
        V24 = IV[20]
        V25 = IV[21]
        V26 = IV[22]
        V27 = IV[23]
        V30 = IV[24]
        V31 = IV[25]
        V32 = IV[26]
        V33 = IV[27]
        V34 = IV[28]
        V35 = IV[29]
        V36 = IV[30]
        V37 = IV[31]
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val ptr = flush()
        tmpBuf[ptr] = 0x80.toByte()
        for (i in ptr + 1..31) tmpBuf[i] = 0x00
        update(tmpBuf, ptr, 32 - ptr)
        for (i in 0 until ptr + 1) tmpBuf[i] = 0x00
        update(tmpBuf, 0, 32)
        encodeBEInt(V00 xor V10 xor V20 xor V30, output, outputOffset + 0)
        encodeBEInt(V01 xor V11 xor V21 xor V31, output, outputOffset + 4)
        encodeBEInt(V02 xor V12 xor V22 xor V32, output, outputOffset + 8)
        encodeBEInt(V03 xor V13 xor V23 xor V33, output, outputOffset + 12)
        encodeBEInt(V04 xor V14 xor V24 xor V34, output, outputOffset + 16)
        encodeBEInt(V05 xor V15 xor V25 xor V35, output, outputOffset + 20)
        encodeBEInt(V06 xor V16 xor V26 xor V36, output, outputOffset + 24)
        encodeBEInt(V07 xor V17 xor V27 xor V37, output, outputOffset + 28)
        update(tmpBuf, 0, 32)
        encodeBEInt(V00 xor V10 xor V20 xor V30, output, outputOffset + 32)
        encodeBEInt(V01 xor V11 xor V21 xor V31, output, outputOffset + 36)
        encodeBEInt(V02 xor V12 xor V22 xor V32, output, outputOffset + 40)
        encodeBEInt(V03 xor V13 xor V23 xor V33, output, outputOffset + 44)
    }

    override fun doInit() {
        tmpBuf = ByteArray(32)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        var tmp: Int
        var a0: Int
        var a1: Int
        var a2: Int
        var a3: Int
        var a4: Int
        var a5: Int
        var a6: Int
        var a7: Int
        var b0: Int
        var b1: Int
        var b2: Int
        var b3: Int
        var b4: Int
        var b5: Int
        var b6: Int
        var b7: Int
        var M0 = decodeBEInt(data, 0)
        var M1 = decodeBEInt(data, 4)
        var M2 = decodeBEInt(data, 8)
        var M3 = decodeBEInt(data, 12)
        var M4 = decodeBEInt(data, 16)
        var M5 = decodeBEInt(data, 20)
        var M6 = decodeBEInt(data, 24)
        var M7 = decodeBEInt(data, 28)
        a0 = V00 xor V10
        a1 = V01 xor V11
        a2 = V02 xor V12
        a3 = V03 xor V13
        a4 = V04 xor V14
        a5 = V05 xor V15
        a6 = V06 xor V16
        a7 = V07 xor V17
        b0 = V20 xor V30
        b1 = V21 xor V31
        b2 = V22 xor V32
        b3 = V23 xor V33
        b4 = V24 xor V34
        b5 = V25 xor V35
        b6 = V26 xor V36
        b7 = V27 xor V37
        a0 = a0 xor b0
        a1 = a1 xor b1
        a2 = a2 xor b2
        a3 = a3 xor b3
        a4 = a4 xor b4
        a5 = a5 xor b5
        a6 = a6 xor b6
        a7 = a7 xor b7
        tmp = a7
        a7 = a6
        a6 = a5
        a5 = a4
        a4 = a3 xor tmp
        a3 = a2 xor tmp
        a2 = a1
        a1 = a0 xor tmp
        a0 = tmp
        V00 = a0 xor V00
        V01 = a1 xor V01
        V02 = a2 xor V02
        V03 = a3 xor V03
        V04 = a4 xor V04
        V05 = a5 xor V05
        V06 = a6 xor V06
        V07 = a7 xor V07
        V10 = a0 xor V10
        V11 = a1 xor V11
        V12 = a2 xor V12
        V13 = a3 xor V13
        V14 = a4 xor V14
        V15 = a5 xor V15
        V16 = a6 xor V16
        V17 = a7 xor V17
        V20 = a0 xor V20
        V21 = a1 xor V21
        V22 = a2 xor V22
        V23 = a3 xor V23
        V24 = a4 xor V24
        V25 = a5 xor V25
        V26 = a6 xor V26
        V27 = a7 xor V27
        V30 = a0 xor V30
        V31 = a1 xor V31
        V32 = a2 xor V32
        V33 = a3 xor V33
        V34 = a4 xor V34
        V35 = a5 xor V35
        V36 = a6 xor V36
        V37 = a7 xor V37
        tmp = V07
        b7 = V06
        b6 = V05
        b5 = V04
        b4 = V03 xor tmp
        b3 = V02 xor tmp
        b2 = V01
        b1 = V00 xor tmp
        b0 = tmp
        b0 = b0 xor V30
        b1 = b1 xor V31
        b2 = b2 xor V32
        b3 = b3 xor V33
        b4 = b4 xor V34
        b5 = b5 xor V35
        b6 = b6 xor V36
        b7 = b7 xor V37
        tmp = V37
        V37 = V36
        V36 = V35
        V35 = V34
        V34 = V33 xor tmp
        V33 = V32 xor tmp
        V32 = V31
        V31 = V30 xor tmp
        V30 = tmp
        V30 = V30 xor V20
        V31 = V31 xor V21
        V32 = V32 xor V22
        V33 = V33 xor V23
        V34 = V34 xor V24
        V35 = V35 xor V25
        V36 = V36 xor V26
        V37 = V37 xor V27
        tmp = V27
        V27 = V26
        V26 = V25
        V25 = V24
        V24 = V23 xor tmp
        V23 = V22 xor tmp
        V22 = V21
        V21 = V20 xor tmp
        V20 = tmp
        V20 = V20 xor V10
        V21 = V21 xor V11
        V22 = V22 xor V12
        V23 = V23 xor V13
        V24 = V24 xor V14
        V25 = V25 xor V15
        V26 = V26 xor V16
        V27 = V27 xor V17
        tmp = V17
        V17 = V16
        V16 = V15
        V15 = V14
        V14 = V13 xor tmp
        V13 = V12 xor tmp
        V12 = V11
        V11 = V10 xor tmp
        V10 = tmp
        V10 = V10 xor V00
        V11 = V11 xor V01
        V12 = V12 xor V02
        V13 = V13 xor V03
        V14 = V14 xor V04
        V15 = V15 xor V05
        V16 = V16 xor V06
        V17 = V17 xor V07
        V00 = b0 xor M0
        V01 = b1 xor M1
        V02 = b2 xor M2
        V03 = b3 xor M3
        V04 = b4 xor M4
        V05 = b5 xor M5
        V06 = b6 xor M6
        V07 = b7 xor M7
        tmp = M7
        M7 = M6
        M6 = M5
        M5 = M4
        M4 = M3 xor tmp
        M3 = M2 xor tmp
        M2 = M1
        M1 = M0 xor tmp
        M0 = tmp
        V10 = V10 xor M0
        V11 = V11 xor M1
        V12 = V12 xor M2
        V13 = V13 xor M3
        V14 = V14 xor M4
        V15 = V15 xor M5
        V16 = V16 xor M6
        V17 = V17 xor M7
        tmp = M7
        M7 = M6
        M6 = M5
        M5 = M4
        M4 = M3 xor tmp
        M3 = M2 xor tmp
        M2 = M1
        M1 = M0 xor tmp
        M0 = tmp
        V20 = V20 xor M0
        V21 = V21 xor M1
        V22 = V22 xor M2
        V23 = V23 xor M3
        V24 = V24 xor M4
        V25 = V25 xor M5
        V26 = V26 xor M6
        V27 = V27 xor M7
        tmp = M7
        M7 = M6
        M6 = M5
        M5 = M4
        M4 = M3 xor tmp
        M3 = M2 xor tmp
        M2 = M1
        M1 = M0 xor tmp
        M0 = tmp
        V30 = V30 xor M0
        V31 = V31 xor M1
        V32 = V32 xor M2
        V33 = V33 xor M3
        V34 = V34 xor M4
        V35 = V35 xor M5
        V36 = V36 xor M6
        V37 = V37 xor M7
        V14 = V14 shl 1 or (V14 ushr 31)
        V15 = V15 shl 1 or (V15 ushr 31)
        V16 = V16 shl 1 or (V16 ushr 31)
        V17 = V17 shl 1 or (V17 ushr 31)
        V24 = V24 shl 2 or (V24 ushr 30)
        V25 = V25 shl 2 or (V25 ushr 30)
        V26 = V26 shl 2 or (V26 ushr 30)
        V27 = V27 shl 2 or (V27 ushr 30)
        V34 = V34 shl 3 or (V34 ushr 29)
        V35 = V35 shl 3 or (V35 ushr 29)
        V36 = V36 shl 3 or (V36 ushr 29)
        V37 = V37 shl 3 or (V37 ushr 29)
        for (r in 0..7) {
            tmp = V00
            V00 = V00 or V01
            V02 = V02 xor V03
            V01 = V01.inv()
            V00 = V00 xor V03
            V03 = V03 and tmp
            V01 = V01 xor V03
            V03 = V03 xor V02
            V02 = V02 and V00
            V00 = V00.inv()
            V02 = V02 xor V01
            V01 = V01 or V03
            tmp = tmp xor V01
            V03 = V03 xor V02
            V02 = V02 and V01
            V01 = V01 xor V00
            V00 = tmp
            tmp = V05
            V05 = V05 or V06
            V07 = V07 xor V04
            V06 = V06.inv()
            V05 = V05 xor V04
            V04 = V04 and tmp
            V06 = V06 xor V04
            V04 = V04 xor V07
            V07 = V07 and V05
            V05 = V05.inv()
            V07 = V07 xor V06
            V06 = V06 or V04
            tmp = tmp xor V06
            V04 = V04 xor V07
            V07 = V07 and V06
            V06 = V06 xor V05
            V05 = tmp
            V04 = V04 xor V00
            V00 = V00 shl 2 or (V00 ushr 30) xor V04
            V04 = V04 shl 14 or (V04 ushr 18) xor V00
            V00 = V00 shl 10 or (V00 ushr 22) xor V04
            V04 = V04 shl 1 or (V04 ushr 31)
            V05 = V05 xor V01
            V01 = V01 shl 2 or (V01 ushr 30) xor V05
            V05 = V05 shl 14 or (V05 ushr 18) xor V01
            V01 = V01 shl 10 or (V01 ushr 22) xor V05
            V05 = V05 shl 1 or (V05 ushr 31)
            V06 = V06 xor V02
            V02 = V02 shl 2 or (V02 ushr 30) xor V06
            V06 = V06 shl 14 or (V06 ushr 18) xor V02
            V02 = V02 shl 10 or (V02 ushr 22) xor V06
            V06 = V06 shl 1 or (V06 ushr 31)
            V07 = V07 xor V03
            V03 = V03 shl 2 or (V03 ushr 30) xor V07
            V07 = V07 shl 14 or (V07 ushr 18) xor V03
            V03 = V03 shl 10 or (V03 ushr 22) xor V07
            V07 = V07 shl 1 or (V07 ushr 31)
            V00 = V00 xor RC00[r]
            V04 = V04 xor RC04[r]
        }
        for (r in 0..7) {
            tmp = V10
            V10 = V10 or V11
            V12 = V12 xor V13
            V11 = V11.inv()
            V10 = V10 xor V13
            V13 = V13 and tmp
            V11 = V11 xor V13
            V13 = V13 xor V12
            V12 = V12 and V10
            V10 = V10.inv()
            V12 = V12 xor V11
            V11 = V11 or V13
            tmp = tmp xor V11
            V13 = V13 xor V12
            V12 = V12 and V11
            V11 = V11 xor V10
            V10 = tmp
            tmp = V15
            V15 = V15 or V16
            V17 = V17 xor V14
            V16 = V16.inv()
            V15 = V15 xor V14
            V14 = V14 and tmp
            V16 = V16 xor V14
            V14 = V14 xor V17
            V17 = V17 and V15
            V15 = V15.inv()
            V17 = V17 xor V16
            V16 = V16 or V14
            tmp = tmp xor V16
            V14 = V14 xor V17
            V17 = V17 and V16
            V16 = V16 xor V15
            V15 = tmp
            V14 = V14 xor V10
            V10 = V10 shl 2 or (V10 ushr 30) xor V14
            V14 = V14 shl 14 or (V14 ushr 18) xor V10
            V10 = V10 shl 10 or (V10 ushr 22) xor V14
            V14 = V14 shl 1 or (V14 ushr 31)
            V15 = V15 xor V11
            V11 = V11 shl 2 or (V11 ushr 30) xor V15
            V15 = V15 shl 14 or (V15 ushr 18) xor V11
            V11 = V11 shl 10 or (V11 ushr 22) xor V15
            V15 = V15 shl 1 or (V15 ushr 31)
            V16 = V16 xor V12
            V12 = V12 shl 2 or (V12 ushr 30) xor V16
            V16 = V16 shl 14 or (V16 ushr 18) xor V12
            V12 = V12 shl 10 or (V12 ushr 22) xor V16
            V16 = V16 shl 1 or (V16 ushr 31)
            V17 = V17 xor V13
            V13 = V13 shl 2 or (V13 ushr 30) xor V17
            V17 = V17 shl 14 or (V17 ushr 18) xor V13
            V13 = V13 shl 10 or (V13 ushr 22) xor V17
            V17 = V17 shl 1 or (V17 ushr 31)
            V10 = V10 xor RC10[r]
            V14 = V14 xor RC14[r]
        }
        for (r in 0..7) {
            tmp = V20
            V20 = V20 or V21
            V22 = V22 xor V23
            V21 = V21.inv()
            V20 = V20 xor V23
            V23 = V23 and tmp
            V21 = V21 xor V23
            V23 = V23 xor V22
            V22 = V22 and V20
            V20 = V20.inv()
            V22 = V22 xor V21
            V21 = V21 or V23
            tmp = tmp xor V21
            V23 = V23 xor V22
            V22 = V22 and V21
            V21 = V21 xor V20
            V20 = tmp
            tmp = V25
            V25 = V25 or V26
            V27 = V27 xor V24
            V26 = V26.inv()
            V25 = V25 xor V24
            V24 = V24 and tmp
            V26 = V26 xor V24
            V24 = V24 xor V27
            V27 = V27 and V25
            V25 = V25.inv()
            V27 = V27 xor V26
            V26 = V26 or V24
            tmp = tmp xor V26
            V24 = V24 xor V27
            V27 = V27 and V26
            V26 = V26 xor V25
            V25 = tmp
            V24 = V24 xor V20
            V20 = V20 shl 2 or (V20 ushr 30) xor V24
            V24 = V24 shl 14 or (V24 ushr 18) xor V20
            V20 = V20 shl 10 or (V20 ushr 22) xor V24
            V24 = V24 shl 1 or (V24 ushr 31)
            V25 = V25 xor V21
            V21 = V21 shl 2 or (V21 ushr 30) xor V25
            V25 = V25 shl 14 or (V25 ushr 18) xor V21
            V21 = V21 shl 10 or (V21 ushr 22) xor V25
            V25 = V25 shl 1 or (V25 ushr 31)
            V26 = V26 xor V22
            V22 = V22 shl 2 or (V22 ushr 30) xor V26
            V26 = V26 shl 14 or (V26 ushr 18) xor V22
            V22 = V22 shl 10 or (V22 ushr 22) xor V26
            V26 = V26 shl 1 or (V26 ushr 31)
            V27 = V27 xor V23
            V23 = V23 shl 2 or (V23 ushr 30) xor V27
            V27 = V27 shl 14 or (V27 ushr 18) xor V23
            V23 = V23 shl 10 or (V23 ushr 22) xor V27
            V27 = V27 shl 1 or (V27 ushr 31)
            V20 = V20 xor RC20[r]
            V24 = V24 xor RC24[r]
        }
        for (r in 0..7) {
            tmp = V30
            V30 = V30 or V31
            V32 = V32 xor V33
            V31 = V31.inv()
            V30 = V30 xor V33
            V33 = V33 and tmp
            V31 = V31 xor V33
            V33 = V33 xor V32
            V32 = V32 and V30
            V30 = V30.inv()
            V32 = V32 xor V31
            V31 = V31 or V33
            tmp = tmp xor V31
            V33 = V33 xor V32
            V32 = V32 and V31
            V31 = V31 xor V30
            V30 = tmp
            tmp = V35
            V35 = V35 or V36
            V37 = V37 xor V34
            V36 = V36.inv()
            V35 = V35 xor V34
            V34 = V34 and tmp
            V36 = V36 xor V34
            V34 = V34 xor V37
            V37 = V37 and V35
            V35 = V35.inv()
            V37 = V37 xor V36
            V36 = V36 or V34
            tmp = tmp xor V36
            V34 = V34 xor V37
            V37 = V37 and V36
            V36 = V36 xor V35
            V35 = tmp
            V34 = V34 xor V30
            V30 = V30 shl 2 or (V30 ushr 30) xor V34
            V34 = V34 shl 14 or (V34 ushr 18) xor V30
            V30 = V30 shl 10 or (V30 ushr 22) xor V34
            V34 = V34 shl 1 or (V34 ushr 31)
            V35 = V35 xor V31
            V31 = V31 shl 2 or (V31 ushr 30) xor V35
            V35 = V35 shl 14 or (V35 ushr 18) xor V31
            V31 = V31 shl 10 or (V31 ushr 22) xor V35
            V35 = V35 shl 1 or (V35 ushr 31)
            V36 = V36 xor V32
            V32 = V32 shl 2 or (V32 ushr 30) xor V36
            V36 = V36 shl 14 or (V36 ushr 18) xor V32
            V32 = V32 shl 10 or (V32 ushr 22) xor V36
            V36 = V36 shl 1 or (V36 ushr 31)
            V37 = V37 xor V33
            V33 = V33 shl 2 or (V33 ushr 30) xor V37
            V37 = V37 shl 14 or (V37 ushr 18) xor V33
            V33 = V33 shl 10 or (V33 ushr 22) xor V37
            V37 = V37 shl 1 or (V37 ushr 31)
            V30 = V30 xor RC30[r]
            V34 = V34 xor RC34[r]
        }
    }

    override fun toString(): String {
        return "Luffa-384"
    }

    companion object {
        private val IV = intArrayOf(
            0x6d251e69, 0x44b051e0, 0x4eaa6fb4, -0x24087b9b,
            0x6e292011, -0x6fead20c, -0x11fa7ec7, -0x2109ef45,
            -0x3c4bb46b, -0x262d0daa, 0x70eee9a0, -0x21f6605d,
            0x5d9b0557, -0x7036bb4d, -0x30e330f2, 0x746cd581,
            -0x8103763, 0x5dba5781, 0x04016ce5, -0x529a63fb,
            0x0306194f, 0x666d1836, 0x24aa230a, -0x74d9b519,
            -0x7a7f8a2b, 0x36d79cce, -0x1a8e0829, 0x204b1f67,
            0x35870c6a, 0x57e9e923, 0x14bcb808, 0x7cde72ce
        )
        private val RC00 = intArrayOf(
            0x303994a6, -0x3f19ad67, 0x6cc33a12, -0x23a967c2,
            0x1e00108f, 0x7800423d, -0x70a4877e, -0x691e24ee
        )
        private val RC04 = intArrayOf(
            -0x1fcc87e8, 0x441ba90d, 0x7f34d442, -0x6c76de81,
            -0x1a57431a, 0x5274baf4, 0x26889ba7, -0x65dd9163
        )
        private val RC10 = intArrayOf(
            -0x4921ef13, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51,
            0x707a3d45, -0x514d7a9e, -0x4535ea77, 0x40a46f3e
        )
        private val RC14 = intArrayOf(
            0x01685f3d, 0x05a17cf4, -0x42f63536, -0xbd8d4d8,
            0x144ae5cc, -0x55851d5, 0x2e48f1c1, -0x46dc38fc
        )
        private val RC20 = intArrayOf(
            -0x3df262e, 0x34552e25, 0x7ad8818f, -0x7bc789b6,
            -0x44921fce, -0x12487f38, -0x267b8caa, -0x5d387bcc
        )
        private val RC24 = intArrayOf(
            -0x1da18d3f, -0x19dc448e, 0x5c58a4a4, 0x1e38e2e7,
            0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7
        )
        private val RC30 = intArrayOf(
            -0x4dec505b, -0x37b1416b, 0x4e608a22, 0x56d858fe,
            0x343b138f, -0x2f13b1c3, 0x2ceb4882, -0x4c52ddf8
        )
        private val RC34 = intArrayOf(
            -0x1fd73641, 0x44756f91, 0x7e8fce32, -0x6a9ab742,
            -0x1e6e41e, 0x3cb226e5, 0x5944a28e, -0x5e3b3cab
        )

        /**
         * Encode the 32-bit word `val` into the array
         * `buf` at offset `off`, in big-endian
         * convention (most significant byte first).
         *
         * @param val   the value to encode
         * @param buf   the destination buffer
         * @param off   the destination offset
         */
        private fun encodeBEInt(`val`: Int, buf: ByteArray, off: Int) {
            buf[off + 0] = (`val` ushr 24).toByte()
            buf[off + 1] = (`val` ushr 16).toByte()
            buf[off + 2] = (`val` ushr 8).toByte()
            buf[off + 3] = `val`.toByte()
        }

        /**
         * Decode a 32-bit big-endian word from the array `buf`
         * at offset `off`.
         *
         * @param buf   the source buffer
         * @param off   the source offset
         * @return  the decoded value
         */
        private fun decodeBEInt(buf: ByteArray, off: Int): Int {
            return (buf[off].toInt() and 0xFF shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
        }
    }
}
