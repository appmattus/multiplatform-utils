package fr.cryptohash

import fr.cryptohash.Digest
import fr.cryptohash.SHA384
import fr.cryptohash.SHA512
import kotlin.test.Test

class SHA2BigCoreTest {

    /**
     * Test SHA-384 implementation.
     */
    @Test
    fun testSHA384() {
        val dig = SHA384()
        testKat(
            dig, "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                    + "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )
        testKat(
            dig, "abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                    + "klmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
                    + "qrsmnopqrstnopqrstu", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"
                    + "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        )
        testKatMillionA(
            dig, "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"
                    + "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
        )
    }

    /**
     * Test SHA-512 implementation.
     */
    @Test
    fun testSHA512() {
        val dig = SHA512()
        testKat(
            dig, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        testKat(
            dig, "abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                    + "klmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
                    + "qrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                    + "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        )
        testKatMillionA(
            dig, (
                    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                            + "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")
        )
    }
}
