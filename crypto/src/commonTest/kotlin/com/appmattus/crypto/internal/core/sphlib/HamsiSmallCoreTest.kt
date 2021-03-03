package com.appmattus.crypto.internal.core.sphlib

import kotlin.test.Test

class HamsiSmallCoreTest {

    /**
     * Test Hamsi-224 implementation.
     */
    @Test
    fun testHamsi224() {
        testKatHex(
            Hamsi224(),
            "",
            "b9f6eb1a9b990373f9d2cb125584333c69a3d41ae291845f05da221f"
        )
        testKatHex(
            Hamsi224(),
            "cc",
            "8bfa48cf172314d558417877cda9be97825128c531165407fc241040"
        )
        testKatHex(
            Hamsi224(),
            "41fb",
            "5eabc4770ad6ab30335ca58de088aa234db09258933ba833113a5fa1"
        )
        testKatHex(
            Hamsi224(),
            "1f877c",
            "15a0b54528fe0f765b50bd340bfb36ae32f106e305aec3b2f42cbec5"
        )
        testKatHex(
            Hamsi224(),
            "c1ecfdfc",
            "0a3a2bf457fdc3fbeb78dfd423afc35d772ab22bdbe2aeb5af481fa1"
        )
        testKatHex(
            Hamsi224(),
            "21f134ac57",
            "1734ca61a3787fedf82fab047784c49e77e8cbfc411ba1836742f15b"
        )
        testKatHex(
            Hamsi224(),
            "c6f50bb74e29",
            "83ac176096fa997bfaf7f053e5050ebe64aa17db1bbd0743b119b250"
        )
        testKatHex(
            Hamsi224(),
            "119713cc83eeef",
            "75c618590df4a2b72977790dc5918b47d5452dc1e35ebb9ab57adaff"
        )
        testKatHex(
            Hamsi224(),
            "4a4f202484512526",
            "a49b5041acea909e7c31c639ed07bf51e8309686c750e152628f8454"
        )
        testKatHex(
            Hamsi224(),
            "1f66ab4185ed9b6375",
            "ccf83b7f505bfc59fcb40e6eff6dccf54040e30ed914a6fb50af20ee"
        )
        testKatHex(
            Hamsi224(),
            "eed7422227613b6f53c9",
            "f1166e96593bee0bf751da5fa44b4dddb411216f84fa21b77971472c"
        )
        testKatHex(
            Hamsi224(),
            "eaeed5cdffd89dece455f1",
            "e39b587eb5d8c0f817aeb507edbdab6ad9b22fb8e875cc330b7d56e2"
        )
        testKatHex(
            Hamsi224(),
            "5be43c90f22902e4fe8ed2d3",
            "fc4a4fc95292da8e513bea6801a264deebb28bf86357eca39831412a"
        )
        testKatHex(
            Hamsi224(),
            "a746273228122f381c3b46e4f1",
            "b5ab10136121523143f6e5f94539d9e710a6b7410ac28e14f24aaf0a"
        )
        testKatHex(
            Hamsi224(),
            "3c5871cd619c69a63b540eb5a625",
            "9068926c8760c5d3c29ee93832cc6996b6613f4ac74391982c600999"
        )
        testKatHex(
            Hamsi224(),
            "fa22874bcc068879e8ef11a69f0722",
            "e4e757d6da0f8bbfa85c886a3b3c3d87a6669c18570f0cd12e76f811"
        )
        testKatHex(
            Hamsi224(),
            "52a608ab21ccdd8a4457a57ede782176",
            "e6ecd4b294a8a023c4b52d79aef2ff44107cd14dfa56f27867af0c97"
        )
        testKatHex(
            Hamsi224(),
            "82e192e4043ddcd12ecf52969d0f807eed",
            "c0e6e2738d539df37d57c5b94310feff6d95417cdfca8f7cf35f7d4c"
        )
        testKatHex(
            Hamsi224(),
            "75683dcb556140c522543bb6e9098b21a21e",
            "452f8f9ed5d8abdaf163fe0dd0809fd9d5b545227b5f042d10e93c54"
        )
        testKatHex(
            Hamsi224(),
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "47130fe5383d4878de71b9db0965fea196ec5d6277fe55bf80ea81c7"
        )
        testKatHex(
            Hamsi224(),
            "e26193989d06568fe688e75540aea06747d9f851",
            "8acd3924d9b6e93d2d0ed1aae299632bfec304baa6c4e644b36f3cd3"
        )
        testKatHex(
            Hamsi224(),
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "3f42b2b3154ae54c1da8de3087f4643010f4af632696c61659f44031"
        )
        testKatHex(
            Hamsi224(),
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "d739ec8597b4af06bd25f3cee4c15094e4845a775f950736c0ab652e"
        )
        testKatHex(
            Hamsi224(),
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "959b6b8c7fd94a456201f602f1852ef6a829c00e254d64f506aa85c8"
        )
        testKatHex(
            Hamsi224(),
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "6970a83589478a58d9f57dd914b1746ff2269114bbe23a664c03a0a7"
        )
        testKatHex(
            Hamsi224(),
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "e652684a2670d9902c154b864addab02d01f3c5a1989dcf465b34e3a"
        )
        testKatHex(
            Hamsi224(),
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "e54ceb2b29e623446cf875f5aeaf82364cafcae4d5003b7e1132bd30"
        )
        testKatHex(
            Hamsi224(),
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "b63007f7e3dca1b1af0d7c5711dee2e1aa66680de1faeb74d50942de"
        )
        testKatHex(
            Hamsi224(),
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "67bd07760ff93fc61a22608ef9eb0f2262d9975aa84aac42c3ba8cff"
        )
        testKatHex(
            Hamsi224(),
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "79652ed9a8f8a7c4fa3629c8baeabdca15a98e1441feab5061e01a14"
        )
        testKatHex(
            Hamsi224(),
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "ad9b3e9f8d91d4ea0310b861df67b303369b50be40bca7c24c49fb67"
        )
        testKatHex(
            Hamsi224(),
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "dbde3421555b22f1469410a2f7fae414484aa6d1562eeb914683a483"
        )
        testKatHex(
            Hamsi224(),
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "66ffd45e37f72bf74f7143df4fe5d4d99d56109dd86d1374d55f3bef"
        )
    }

    /**
     * Test Hamsi-256 implementation.
     */
    @Test
    fun testHamsi256() {
        testKatHex(
            Hamsi256(),
            "",
            "750e9ec469f4db626bee7e0c10ddaa1bd01fe194b94efbabebd24764dc2b13e9"
        )
        testKatHex(
            Hamsi256(),
            "cc",
            "ac2dac2a6ddaf703b7a55745d61b1a16a3d1bf1f74caab265a2e5dbebcf60832"
        )
        testKatHex(
            Hamsi256(),
            "41fb",
            "2db4f6b7a8e20b28d5d3d536ea23ade6566d4e622e62a108cd52a7a809c469dd"
        )
        testKatHex(
            Hamsi256(),
            "1f877c",
            "cb596913e691f8654a613e24debf3262e6477fd737d5c422e670e0c75fae7d17"
        )
        testKatHex(
            Hamsi256(),
            "c1ecfdfc",
            "aeaef9b3b7f8f947fba5fe9bd9886a203110621bc2bca6ac890997aeec69ae0e"
        )
        testKatHex(
            Hamsi256(),
            "21f134ac57",
            "b302060a7649a5872109e845fe20c3c427021e45e91d680445980529374a598d"
        )
        testKatHex(
            Hamsi256(),
            "c6f50bb74e29",
            "15aa66c5e6a2f5274739bb0d47f7f2ba9a0efa76356d3cbdc0b00efc92a3848d"
        )
        testKatHex(
            Hamsi256(),
            "119713cc83eeef",
            "b3d4f87d62c404d11b1b6bc244f53bd75db2d8def1911bbc1d9631a8d4f01cfb"
        )
        testKatHex(
            Hamsi256(),
            "4a4f202484512526",
            "452866b4f08d190fede099473368aa2b187acc0320a4918b9a3e74795123e816"
        )
        testKatHex(
            Hamsi256(),
            "1f66ab4185ed9b6375",
            "271d8b8e833fcac17e0b487ba0f7ee8ddc41a3d34db3390e7ab7e536d71e8564"
        )
        testKatHex(
            Hamsi256(),
            "eed7422227613b6f53c9",
            "2b854a5ed0d7d6f6d82e501e2efafe6b10b8372b3c478b5829bb78d9bcd5466f"
        )
        testKatHex(
            Hamsi256(),
            "eaeed5cdffd89dece455f1",
            "6c507361898ac38fef0c18ce19a5110b73580c1b2499571287afb39f355545f0"
        )
        testKatHex(
            Hamsi256(),
            "5be43c90f22902e4fe8ed2d3",
            "5562d17fdb376211004b0c1723be2d9263f8d05dc5feba26fde400bef38dc068"
        )
        testKatHex(
            Hamsi256(),
            "a746273228122f381c3b46e4f1",
            "be54b3bda29df786bbd9c460d71c741537bf38cc218357e5fb10b717f8b7f828"
        )
        testKatHex(
            Hamsi256(),
            "3c5871cd619c69a63b540eb5a625",
            "08f9978ecaf15426c5eaedf68e70a59a69e272c367cd4fe7e8dc7f596dbb50f2"
        )
        testKatHex(
            Hamsi256(),
            "fa22874bcc068879e8ef11a69f0722",
            "7f9bc754ee10f4bc8eb4bddee72596b15a2997b5ecaf0f1f1cbe307d8f55d73c"
        )
        testKatHex(
            Hamsi256(),
            "52a608ab21ccdd8a4457a57ede782176",
            "7baf8489b17492fa2ce40e43ac06d9b9adbf62d40fcb4e07b47368605a13c2c8"
        )
        testKatHex(
            Hamsi256(),
            "82e192e4043ddcd12ecf52969d0f807eed",
            "eef7d7d34393f676e8c0140e8bef06fb09c8e039a58c332fa29afa18aaabca4e"
        )
        testKatHex(
            Hamsi256(),
            "75683dcb556140c522543bb6e9098b21a21e",
            "e36e7e76f7d84ad64f9fc47d8ae6a7b240782fd7777c84e8dd7b1db64c6b74da"
        )
        testKatHex(
            Hamsi256(),
            "06e4efe45035e61faaf4287b4d8d1f12ca97e5",
            "b2ca5c9dd4814b0eda0494043c669274438671a8af9bfc523388af660dd98d38"
        )
        testKatHex(
            Hamsi256(),
            "e26193989d06568fe688e75540aea06747d9f851",
            "b7797a0dec418d3b0c152cf093d93ff31fcd11774fdb345dd2a836aeeccbba63"
        )
        testKatHex(
            Hamsi256(),
            "d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a",
            "eed455bc166c62daa2514d5e69c1abc439e8c256c43d0bce222b1ff7336ac1b5"
        )
        testKatHex(
            Hamsi256(),
            "57085fd7e14216ab102d8317b0cb338a786d5fc32d8f",
            "172765f4a3dcabfae32604922562ba9565aa7625985ab02094744b7e790db0af"
        )
        testKatHex(
            Hamsi256(),
            "a05404df5dbb57697e2c16fa29defac8ab3560d6126fa0",
            "4628287e95a93360ab9f5aec1f4bbd86e708c1843c6d8838d62c25028f8046f8"
        )
        testKatHex(
            Hamsi256(),
            "aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6",
            "07556a3a185ffe16367e84d8f21fb3a04174a1000d023e12697518b7f942887f"
        )
        testKatHex(
            Hamsi256(),
            "aafdc9243d3d4a096558a360cc27c8d862f0be73db5e88aa55",
            "bd2b4dbd24031f53236792744bb796f9713861978793894ef548394426d09e88"
        )
        testKatHex(
            Hamsi256(),
            "7bc84867f6f9e9fdc3e1046cae3a52c77ed485860ee260e30b15",
            "8bc5d7e1ab86dc47a2a784ba7823f9ac5906ce79feeb98021c55bfb33226fca4"
        )
        testKatHex(
            Hamsi256(),
            "fac523575a99ec48279a7a459e98ff901918a475034327efb55843",
            "6a71ec1e389034fd1008e386f023ee0b7a6265603a90856e86051998d058a83e"
        )
        testKatHex(
            Hamsi256(),
            "0f8b2d8fcfd9d68cffc17ccfb117709b53d26462a3f346fb7c79b85e",
            "6ad9f71c8d319756e8e3c180f1bd0b394e6bc0f13940d7b8880949fee2eba8de"
        )
        testKatHex(
            Hamsi256(),
            "a963c3e895ff5a0be4824400518d81412f875fa50521e26e85eac90c04",
            "2be2ef84939028c0c70987d89d58fc927e6142177b13b42f0988005909830468"
        )
        testKatHex(
            Hamsi256(),
            "03a18688b10cc0edf83adf0a84808a9718383c4070c6c4f295098699ac2c",
            "debde7a74f3533350328f8cd014959dc1a6bf179d7782e5592967f49a867dc74"
        )
        testKatHex(
            Hamsi256(),
            "84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29",
            "6372ad8a4be2ea8d6387f95ec897a1609d477f0f791ab2a9db34595f489172f5"
        )
        testKatHex(
            Hamsi256(),
            "9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10",
            "6e72391d5be0769c20d92aebee0b1772939e31d521bca1d25f2add261e920ec1"
        )
    }
}