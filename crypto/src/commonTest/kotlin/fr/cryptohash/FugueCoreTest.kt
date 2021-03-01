package fr.cryptohash

import kotlin.test.Test

class FugueCoreTest {

    /**
     * Test Fugue-384 implementation.
     */
    @Test
    fun testFugue384() {
        testKatHex(
            Fugue384(),
            "",
            "466d05f6812b58b8628e53816b2a99d173b804a964de971829159c3791ac8b524eebbf5fc73ba40ea8eea446d5424a30"
        )
        testKatHex(
            Fugue384(),
            "cc",
            "436868cd6804b803dac432ed561bb40f91f624a10f2a368702359841cfda6909115628ca4977b3f8063a3b87fc7a0984"
        )
        testKatHex(
            Fugue384(),
            "41fb",
            "faf69841ca96ec8f96657f2871c1ddf9a060e5d55cd7e196078aa920171f73e5373ecda45b4552590124d280e22d9be6"
        )
        testKatHex(
            Fugue384(),
            "1f877c",
            "47fc7c9df32d8ffad51d840de2da1908dd0993340e965b425f8bbba468239973e349394bcfe288b4ee467772bfd26939"
        )
        testKatHex(
            Fugue384(),
            "c1ecfdfc",
            "7092b797e08636119ea45a145c83cce0d1155b00c82306b471a90f9ca1bfa6539ea0ce3e430aaeaefd84655c7aec657a"
        )
        testKatHex(
            Fugue384(),
            "21f134ac57",
            "be4194a2b73651814631cbdd73b97719f863abee2f3e71ae4aeee348843ce2f068fb08b49fccaaf8ec917c75c39b6202"
        )
        testKatHex(
            Fugue384(),
            "c6f50bb74e29",
            "ad340157dd68e0c8af60d8e926b0e3a721d93627da58fa77c4df14df56c324e4f711e64c0ad6346a949ecf0185ab6e1f"
        )
        testKatHex(
            Fugue384(),
            "119713cc83eeef",
            "9e0de23dfc4fa638ddd4be133fe4b917b95d3a908cb07b4cd150a914f7e13ce9dea30513354c4b85d87fe339f8cce6d5"
        )
        testKatHex(
            Fugue384(),
            "4a4f202484512526",
            "6cc5b658be0426dc9da6d09746a7f9f34674358fe439a1d25c12158cd942288543830811fe62bb2c6c2ea099b40aa978"
        )
        testKatHex(
            Fugue384(),
            "1f66ab4185ed9b6375",
            "406ff81f324a86c6e4e97ea79ff86f6601824a1e8599e00817237ca0343f31b835f655a5d9d722c80c64201902c9389a"
        )
        testKatHex(
            Fugue384(),
            "eed7422227613b6f53c9",
            "8ced5b9b5f0c5771d869b8423117b39511fefeaee1dea47368473ec65ee0c0e02b9f41a3b64c6fa65f4ba520bfd36ff0"
        )
        testKatHex(
            Fugue384(),
            "eaeed5cdffd89dece455f1",
            "769551d5a86e56dc424d05a47910c816eb1d5d9c1f2daceffbb6837999d80f77a7c802bb93e9672e47e4588b4187bec2"
        )
        testKatHex(
            Fugue384(),
            "5be43c90f22902e4fe8ed2d3",
            "0781e232a61cf7c40458a453fdcebb5fc02b2c52289d1005689ab77fd3de44da7b2f009eb7e769ce70a14a830ed37eb8"
        )
        testKatHex(
            Fugue384(),
            "a746273228122f381c3b46e4f1",
            "dbd226b023247f4e790d09ba98594a1ebf24b2dac8e6c46c620ef9967dd65190b9e9567ab06b0d511c2443788d46d86d"
        )
        testKatHex(
            Fugue384(),
            "3c5871cd619c69a63b540eb5a625",
            "76ece1c5dda393c24c98804cb5e93f69e6075d9fa8f7cbe3f695c6ef16a26757dd628efb83ffc92aad4dd774396016a0"
        )
        testKatHex(
            Fugue384(),
            "fa22874bcc068879e8ef11a69f0722",
            "e3aee6fd30da64998daa2910f4c16355fbf5c06bd8499eb0d31d4b3dfd0ad68b63afbf32398f24b4910d99a3784978f6"
        )
        testKatHex(
            Fugue384(),
            "52a608ab21ccdd8a4457a57ede782176",
            "04847908c63e56a9d0e662a81ea05dddaf3eafcb711e6e16311d4c5090df0d73da31b5672b660bc59b679dae9d569c3b"
        )
    }

    /**
     * Test Fugue-512 implementation.
     */
    @Test
    fun testFugue512() {
        testKatHex(
            Fugue512(),
            "",
            "3124f0cbb5a1c2fb3ce747ada63ed2ab3bcd74795cef2b0e805d5319fcc360b4617b6a7eb631d66f6d106ed0724b56fa8c1110f9b8df1c6898e7ca3c2dfccf79"
        )
        testKatHex(
            Fugue512(),
            "cc",
            "2ef4115479b060fc64a4d6f6913a39e326afc81deb4e39d71c573df5ed132200e7c784bab1804930cad16847f16cbda59a865bbd928ebc17d33689fef233c10b"
        )
        testKatHex(
            Fugue512(),
            "41fb",
            "f42d0817ef7fe50afec87cdd1b934d16bfb575df4feda7e65d09b592b0318920d9b1d1f89bdff9aa4c6ab5f058d692ab0d5d431e860f6ac6be70f47ab124abd8"
        )
        testKatHex(
            Fugue512(),
            "1f877c",
            "deea1a90bf692f13974943e0ceeb551cf94903bde784278fb52a2b61750d093ab4eb662edb36ffc3c184ce753621173928e5fa58f7df7449d8888a56f238d936"
        )
        testKatHex(
            Fugue512(),
            "c1ecfdfc",
            "016a26bed81a1af68dc64e4089878b89c660ac5faa61fcf9f4eda88b5fd62e4786b66e295b94992887e0bb95bf802c4c35aada89d5c2f77ecc4d6fc7546114b6"
        )
        testKatHex(
            Fugue512(),
            "21f134ac57",
            "dfed15e291c38285ab66277bd772726f63c07080111571932006c3ab7b448414cc13402d3ad25eb75021826fe8fbda01c390db1fb26f282c831e9e72d0d54391"
        )
        testKatHex(
            Fugue512(),
            "c6f50bb74e29",
            "172dd6328695a30e9dbd7d6f805b43836f1003c242be47d95d83a4f0a7bbc6d7b0e84697002fb7707fdeaa305c60adb56a6a9b25b227a3fe16cd6602742f5125"
        )
        testKatHex(
            Fugue512(),
            "119713cc83eeef",
            "dbe9ea70da3a77202beb3398ee457aa4898e4b4b5cb76e14088bf95f1245a5864c07898662db493eeb2b497e77446c8886dd9b830641d6e1b57e6cdf7c797a24"
        )
        testKatHex(
            Fugue512(),
            "4a4f202484512526",
            "90a0be0248e8edc3402fc2322e6c8e7a9d7e4a2752f771ff7d8baed84320220052388f19577e13335290f1e7fdf3a24fc9fa332f6da55e2b75744972809048be"
        )
        testKatHex(
            Fugue512(),
            "1f66ab4185ed9b6375",
            "9f3408b8ca6fa07e7c760c86d237ecc4be7beb5866fc18fb8d146e57d2e96950f77f634c3fbd4214618a49075fd70573dcaee15c05d8d5fb71e82d33e5df88ca"
        )
        testKatHex(
            Fugue512(),
            "eed7422227613b6f53c9",
            "c98a7a5c4795a41d2c8334f97f58e6f00d6c69a46b22ef36e09412347d5756b142439d7402f1f528a9060c022723a644f12c7a2cc53512edfb0692d24774cf21"
        )
        testKatHex(
            Fugue512(),
            "eaeed5cdffd89dece455f1",
            "5aa080d029dc20bebce3889e9bcde9346ec7593165b18f18979defa6f7285c6928d1bc443774aadf76f192f2c1938311888f12f60b513bd895807b6a37ededf2"
        )
        testKatHex(
            Fugue512(),
            "5be43c90f22902e4fe8ed2d3",
            "f0f44737795ecd12c99a88befb62637ca1abf82d2d600c03c98c1bff97ee922df1d94ca0e54f7aec6e2b59da400d4b5c666980e3cf46952a9735624037a7b7cb"
        )
        testKatHex(
            Fugue512(),
            "a746273228122f381c3b46e4f1",
            "83353c99afcddb4af32911c01b2724bafc1c433c3b5d3e89ceba512d655425a0bfe20bdd787e784065c177158d8937a39b8e26d9f531b3164d077059a6021291"
        )
        testKatHex(
            Fugue512(),
            "3c5871cd619c69a63b540eb5a625",
            "5707b902292411e8bc8b63f675d568507f98ca3c0dcca18ad72908bc2e2aa9bb9f3a9349867a6badf71bb55f2612e9f59ad25d7f00b270ed581e065089b90812"
        )
        testKatHex(
            Fugue512(),
            "fa22874bcc068879e8ef11a69f0722",
            "fac660712af881891ff7f9d8eebad3d7cf83c1f7ee2fa393db4aea68cb2521ac51767606493cd5710ef429008fd248c6cdbe9b8e3bd9240da2de653bdbc0098f"
        )
        testKatHex(
            Fugue512(),
            "52a608ab21ccdd8a4457a57ede782176",
            "4d047431c2f0c6bab89982425138a86eb042f72d59847d13c8a3cb6541a25b31383704d24c0133edf675f4011566debec0f14ccb65503056234bb11bec5e58b4"
        )
    }
}