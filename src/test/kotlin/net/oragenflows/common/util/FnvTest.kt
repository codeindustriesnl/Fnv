package net.oragenflows.common.util

import io.kotest.matchers.shouldBe
import net.orangeflows.common.util.Fnv
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.util.Arrays


/**
 * Tests the FNV hash functions. Test values for FNV-constant hash sizes taken from
 * [https://nqv.github.io/fnv/](https://nqv.github.io/fnv/).
 */
internal class FNVTest() {
    @BeforeEach
    fun setUp() {
    }

    @Test
    fun fnv1() {

        // String to hash
        val hashme = "asdfasdfasdfasdf".toByteArray()

        // FNV1 hash values of "asdfasdfasdfasdf"
        val fnv32 = BigInteger("8d968dbd", 16).toByteArray()
        val fnv64 = BigInteger("9699ecfed4303f9d", 16).toByteArray()
        val fnv128 = BigInteger("b24f15c98fa3cdab34062052dd618045", 16).toByteArray()
        val fnv256 = BigInteger(
            "247bd2af7549ce3d3e19122f9371a39cf51a37d505b75f74780e"
                    + "4b295363026d", 16
        ).toByteArray()
        val fnv512 = BigInteger(
            ("e6976a11387e07a3b308581b3eb0cc4a1430124f02d52bceb7da"
                    + "26f14d3a4251df9a3485fe71fab8b81025e317c89e541276b9119be920b215025bcfffad7"
                    + "ae1"), 16
        ).toByteArray()
        val fnv1024 = BigInteger(
            ("f5ed8ba10097026e4bdf6ed8dff81d35e8cb50cdea1d312ed2f"
                    + "074335406b0d702b8f82d01c703315cfaf500000000000000000000000000000000000000"
                    + "000000000000000000000000000014e0e64e8b1537e8b39bdf3c9cf101ec642a361bad215"
                    + "10f30a045752ac61445ef90e49316e567dadc65bbc57885811e95448fc3"),
            16
        ).toByteArray()
        Assertions.assertTrue(Arrays.equals(fnv32, Fnv.fnv1(hashme, 32)))
        Assertions.assertTrue(Arrays.equals(fnv64, Fnv.fnv1(hashme, 64)))
        Assertions.assertTrue(Arrays.equals(fnv128, Fnv.fnv1(hashme, 128)))
        Assertions.assertTrue(Arrays.equals(fnv256, Fnv.fnv1(hashme, 256)))
        Assertions.assertTrue(Arrays.equals(fnv512, Fnv.fnv1(hashme, 512)))
        Assertions.assertTrue(Arrays.equals(fnv1024, Fnv.fnv1(hashme, 1024)))

        // XOR-folded hashes
        val fnv19 = BigInteger("069C0F", 16).toByteArray()
        val fnv1019 = BigInteger(
            ("05ED8BA10097026E4BDF6ED8DFF81D35E8CB50CDEA1D312ED2F"
                    + "074335406B0D702B8F82D01C703315CFAF500000000000000000000000000000000000000"
                    + "000000000000000000000000000014E0E64E8B1537E8B39BDF3C9CF101EC642A361BAD215"
                    + "10F30A045752AC61445EF90E49316E567DADC65BBC57885811E95448FDD"),
            16
        ).toByteArray()
        Assertions.assertTrue(Arrays.equals(fnv19, Fnv.fnv1(hashme, 19)))
        Assertions.assertTrue(Arrays.equals(fnv1019, Fnv.fnv1(hashme, 1019)))
    }

    @Test
    fun fnv1a() {

        // String to hash
        val hashme = "asdfasdfasdfasdf".toByteArray()

        // FNV1a hash values of "asdfasdfasdfasdf"
        val fnva32 = BigInteger("f4a8096d", 16).toByteArray()
        val fnva64 = BigInteger("78fdb7e8e153064d", 16).toByteArray()
        val fnva128 = BigInteger(
            "36d541ea22f38b65b818f0e16f3c23d5",
            16
        ).toByteArray()
        val fnva256 = BigInteger(
            ("2854f27942424ecd4c8f822f9371ba3b198a71f5808038f7bd6"
                    + "3acb0256f34dd"), 16
        ).toByteArray()
        val fnva512 = BigInteger(
            ("e6976a10939ce1d7dfeeb6db18e011f886fae4e612d52bceb7d"
                    + "a26f14d3a4251df9a3485fe71fab8b81025e317c8908720c0b81cb38a73c0a6f6ea28820d"
                    + "e331"), 16
        ).toByteArray()
        val fnva1024 = BigInteger(
            ("f5ed8ba10097026e4bdf6ed8dff81d35e8cb50cdea1d312ed2"
                    + "f5e51dd1fd24bea2b76593d4bbe914b44e750000000000000000000000000000000000000"
                    + "0000000000000000000000000000014e0e64e8b1537e8b39bdf3c9cf101ec642a361bad21"
                    + "510f30a045752ac61445ef916b8c8b145ca2de98f5134e622fbdad505023"),
            16
        ).toByteArray()
        Assertions.assertTrue(Arrays.equals(fnva32, Fnv.fnv1a(hashme, 32)))
        Assertions.assertTrue(Arrays.equals(fnva64, Fnv.fnv1a(hashme, 64)))
        Assertions.assertTrue(Arrays.equals(fnva128, Fnv.fnv1a(hashme, 128)))
        Assertions.assertTrue(Arrays.equals(fnva256, Fnv.fnv1a(hashme, 256)))
        Assertions.assertTrue(Arrays.equals(fnva512, Fnv.fnv1a(hashme, 512)))
        Assertions.assertTrue(Arrays.equals(fnva1024, Fnv.fnv1a(hashme, 1024)))

        // XOR-folded hashes
        val fnv19 = BigInteger("17F8", 16).toByteArray()
        val fnv1019 = BigInteger(
            ("05ED8BA10097026E4BDF6ED8DFF81D35E8CB50CDEA1D312ED2F"
                    + "5E51DD1FD24BEA2B76593D4BBE914B44E7500000000000000000000000000000000000000"
                    + "000000000000000000000000000014E0E64E8B1537E8B39BDF3C9CF101EC642A361BAD215"
                    + "10F30A045752AC61445EF916B8C8B145CA2DE98F5134E622FBDAD50503D"),
            16
        ).toByteArray()
        Assertions.assertTrue(Arrays.equals(fnv19, Fnv.fnv1a(hashme, 19)))
        Assertions.assertTrue(Arrays.equals(fnv1019, Fnv.fnv1a(hashme, 1019)))
    }

    @Test
    fun `random sentences generated should not have the same hash`() {
        val chars = "abcdefghijklmnopqurstuvwxyz".toList()
        val bigIntegerMutableList = mutableListOf<BigInteger>()
        val intMutableList = mutableListOf<Int>()
        repeat(10000) {
            var sentence = ""
            repeat(10) {
                sentence += chars[kotlin.random.Random.nextInt(0, 26)]

            }
            val signature = Fnv.fnv1(sentence.toByteArray(), 160).reversedArray()

            val byteSignature = Int.readFromByteArray(signature)
            val bigIntSignature = BigInteger(signature)

            bigIntegerMutableList.add(bigIntSignature)
            intMutableList.add(byteSignature)
        }

        val duplicatesByte = intMutableList.groupingBy { it }.eachCount().filter { it.value > 1 }
        duplicatesByte shouldBe emptyMap()

        val duplicatesBig = bigIntegerMutableList.groupingBy { it }.eachCount().filter { it.value > 1 }
        duplicatesBig shouldBe emptyMap()
    }
}

private fun Int.Companion.readFromByteArray(signature: ByteArray): Int {
    var result: Int = 0
    for (i in 0..SIZE_BYTES) {
        val value = signature.getOrNull(i) ?: 0
        result = result shl 8
        result = result or value.toUByte().toInt()
    }
    return result
}
