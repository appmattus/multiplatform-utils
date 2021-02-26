package com.appmattus.crypto

import fr.cryptohash.Fugue224
import fr.cryptohash.Fugue256
import kotlin.test.Test

class Fugue2CoreTest {

    /**
     * Test Fugue-224 implementation.
     */
    @Test
    fun testFugue224() {
        testKatHex(
            Fugue224(),
            "",
            "e2cd30d51a913c4ed2388a141f90caa4914de43010849e7b8a7a9ccd"
        )
        testKatHex(
            Fugue224(),
            "cc",
            "34602ea95b2b9936b9a04ba14b5dc463988df90b1a46f90dd716b60f"
        )
        testKatHex(
            Fugue224(),
            "41fb",
            "17042ef3c9203a838978356cc8debcb90b49a7a3f9862c4c96385e2b"
        )
        testKatHex(
            Fugue224(),
            "1f877c",
            "c4e858280a095030c40cdbe1fd0044632ed28f1b85fbde9b48bc3efd"
        )
        testKatHex(
            Fugue224(),
            "c1ecfdfc",
            "edfdf5a0c8b1ce7c5b7818c670c302745cb61fd4468c04bf36644497"
        )
        testKatHex(
            Fugue224(),
            "21f134ac57",
            "b24848f32ac54150b4f616d12870039db2fdf026b7240edf1846fed1"
        )
        testKatHex(
            Fugue224(),
            "c6f50bb74e29",
            "74b3eaf5370935cc997df0ff6b196906f582a951b546a3d38710e3c5"
        )
        testKatHex(
            Fugue224(),
            "119713cc83eeef",
            "110cf2d9f57c14c0baaeaa2ed9b0162fbd0822a8604d53cdb8f710a6"
        )
        testKatHex(
            Fugue224(),
            "4a4f202484512526",
            "60df1c33c1be7812e229ec0cea34cdc5293030cc65178a110baaa52f"
        )
        testKatHex(
            Fugue224(),
            "1f66ab4185ed9b6375",
            "a30765b87a69e56cb02f52802503d90ea23c37bb57a3dd3f9a6ea9df"
        )
        testKatHex(
            Fugue224(),
            "eed7422227613b6f53c9",
            "d1644b980cf16d6521bc708ac8968e746786ad310e6a62b17f43cb8d"
        )
        testKatHex(
            Fugue224(),
            "eaeed5cdffd89dece455f1",
            "cb08ea526c9c09a9d00324814606bf2f39af42e30e7c3b7f928b5612"
        )
        testKatHex(
            Fugue224(),
            "5be43c90f22902e4fe8ed2d3",
            "9a1c402f1341196352ee4da65ffcbb533536bfc5707e14787f6998bf"
        )
        testKatHex(
            Fugue224(),
            "a746273228122f381c3b46e4f1",
            "14e33b0f2de5276187769bfc3fd5b2b38cc39294a171e1234af56bd2"
        )
        testKatHex(
            Fugue224(),
            "3c5871cd619c69a63b540eb5a625",
            "e00371eb6928b1ec78a09fd9baa2dc17191ee8d264ccf22e507692f4"
        )
        testKatHex(
            Fugue224(),
            "fa22874bcc068879e8ef11a69f0722",
            "61f80d7464346f7bc9ed8a6b514c326e7c7ba9ed2139c3d0c301782f"
        )
        testKatHex(
            Fugue224(),
            "52a608ab21ccdd8a4457a57ede782176",
            "a75d1c8177dce2df14a9fefa25be85fe9a810e665816beb013268fcb"
        )
    }

    /**
     * Test Fugue-256 implementation.
     */
    @Test
    fun testFugue256() {
        testKatHex(
            Fugue256(),
            "",
            "d6ec528980c130aad1d1acd28b9dd8dbdeae0d79eded1fca72c2af9f37c2246f"
        )
        testKatHex(
            Fugue256(),
            "cc",
            "b894eb2df58162f6c48d495f156e73bd086dd13db407ee38781177bb23d129bb"
        )
        testKatHex(
            Fugue256(),
            "41fb",
            "584827dea879a043438c23a32c42ba0990f0f8ce385852693b7eeb2bc4d7fab1"
        )
        testKatHex(
            Fugue256(),
            "1f877c",
            "f9f5cf602b093c43bf9c6d551f6a9e60214ce1bb3a6d842c3d9a5f358df05547"
        )
        testKatHex(
            Fugue256(),
            "c1ecfdfc",
            "9041d9edf413cf0a8cfb6aed97c13032315319438be004685f4bb583f67acf23"
        )
        testKatHex(
            Fugue256(),
            "21f134ac57",
            "2fca43424b89301d8e1ba3c5eb760a8633639b35c5d72331c0a26ed4aee7e4ba"
        )
        testKatHex(
            Fugue256(),
            "c6f50bb74e29",
            "70d683f0b39d3016fc243355a2e40a7f1337aa826fc88785a3f15c0d5e96eb1c"
        )
        testKatHex(
            Fugue256(),
            "119713cc83eeef",
            "5fb6e8b104bd05ff4b4606a5dbc204b1996ceac8721a0f988596ceb6ca38e431"
        )
        testKatHex(
            Fugue256(),
            "4a4f202484512526",
            "84e8df742af4ab3f552a148485a1d27943b57ba748b76a1cdf8e1f054bed3d7b"
        )
        testKatHex(
            Fugue256(),
            "1f66ab4185ed9b6375",
            "0f0e687507e64d63234cc50e627dd1a0a51c6c06ad45fb32604c5921e37daa2a"
        )
        testKatHex(
            Fugue256(),
            "eed7422227613b6f53c9",
            "3cfb02bd515e9d983cc1665ad9368f77c89fee97eb574bf7db8c3d8e44396fb9"
        )
        testKatHex(
            Fugue256(),
            "eaeed5cdffd89dece455f1",
            "2cf0a9ba776998481c86cc66ae958942cc2e0ccc72b4094d8628731c0a9366b8"
        )
        testKatHex(
            Fugue256(),
            "5be43c90f22902e4fe8ed2d3",
            "d94c33e8312522b6393ebdfb4c99137265c8965782e4d7b4495640bfd6a75760"
        )
        testKatHex(
            Fugue256(),
            "a746273228122f381c3b46e4f1",
            "6fcedcfd9d830702c0e4efcbb19a305449f402a6e7f02bf4236c8bae69f28b31"
        )
        testKatHex(
            Fugue256(),
            "3c5871cd619c69a63b540eb5a625",
            "140bb7182339669ea91422ef67f332c7048d5e4a14875b3fda16d2ec5432dc46"
        )
        testKatHex(
            Fugue256(),
            "fa22874bcc068879e8ef11a69f0722",
            "af6e59a0291236d31c8ed4e05dd121125dcd9b70411dfa9d2e2be7423ed2d358"
        )
        testKatHex(
            Fugue256(),
            "52a608ab21ccdd8a4457a57ede782176",
            "3260f5be7147be7db0aefa571bf0fef651bbcb1796513572ee66855492e893d7"
        )
    }
}
