package net.orangeflows.common.util

import java.math.BigInteger


/**
 * Calculating Fowler-Noll-Vo FNV-1 and FNV-1a hashes as described in IETF draft
 * [The FNV Non-Cryptographic Hash
 * Algorithm](https://tools.ietf.org/html/draft-eastlake-fnv-12), including xor-folding for hash lengths other than the FNV constant sizes.
 *
 * Based loosely on the Java code sample by Stefan Santesson in IETF draft
 * [Transport Layer
 * Security (TLS) Cached Information Extension](https://tools.ietf.org/html/draft-ietf-tls-cached-info-08).
 */
object Fnv {
    // FNV Primes
    private val FNV_32_PRIME = BigInteger("16777619")
    private val FNV_64_PRIME = BigInteger("1099511628211")
    private val FNV_128_PRIME = BigInteger("309485009821345068724781371")
    private val FNV_256_PRIME = BigInteger("374144419156711147060143317175368453031918731002211")
    private val FNV_512_PRIME = BigInteger(
        "35835915874844867368919076489095108449946327955754392558399825"
                + "615420669938882575126094039892345713852759"
    )
    private val FNV_1024_PRIME = BigInteger(
        ("50164565101131186554345988110352789550307653454047907443030175"
                + "23831112055108147451509157692220295382716162651878526895249385292291816524375"
                + "083746691371804094271873160484737966720260389217684476157468082573")
    )

    // FNV Basis
    private val FNV_32_BASIS = BigInteger("2166136261")
    private val FNV_64_BASIS = BigInteger("14695981039346656037")
    private val FNV_128_BASIS = BigInteger("144066263297769815596495629667062367629")
    private val FNV_256_BASIS = BigInteger(
        ("10002925795805258090707096862062570483709279601424119394522528"
                + "4501741471925557")
    )
    private val FNV_512_BASIS = BigInteger(
        ("96593031294966694980094354007163104660904187456726378961083743"
                + "29434462657994582932197716438449813051892206539805784495328239340083876191928"
                + "701583869517785")
    )
    private val FNV_1024_BASIS = BigInteger(
        ("14197795064947621068722070641403218320880622795441933960878474"
                + "91461758272325229673230371772215086409652120235554936562817466910857181476047"
                + "10150761480297559698040773201576924585630032153049571501574036444603635505054"
                + "12711285966361610267868082893823963790439336411086884584107735010676915")
    )

    // Modulo Values
    private val FNV_32_MOD = BigInteger("2").pow(32)
    private val FNV_64_MOD = BigInteger("2").pow(64)
    private val FNV_128_MOD = BigInteger("2").pow(128)
    private val FNV_256_MOD = BigInteger("2").pow(256)
    private val FNV_512_MOD = BigInteger("2").pow(512)
    private val FNV_1024_MOD = BigInteger("2").pow(1024)

    // XOR Int
    private const val FNV_XOR = 255

    /**
     * Calculates the FNV-1 hash, then XOR folds to achieve the desired length if the length
     * parameter is not one of {32, 64, 128, 256, 512, 1024}. Hash lengths longer than 1024
     * bits are not supported. Note that hash lengths which are not a multiple of 8 will
     * result in a byte array with some number (8 -(length mod 8)) of leading zeros.
     *
     * @param inp the byte array to be hashed
     * @param length the desired length (in bits) of the hash
     * @return the hash result
     * @throws UnsupportedOperationException length is less than 16 or more than 1024
     */
    @Throws(UnsupportedOperationException::class)
    fun fnv1(inp: ByteArray, length: Int): ByteArray {
        var hash: BigInteger

        val (basis, prime, mod, foldingNeeded) = getParameters(length)
        hash = fnv1_noXor(inp,basis,prime,mod)
        if(foldingNeeded) {
            hash = xorFold(hash, length)
        }
        // Return the byte array, note that it is always 1 bit longer than requested
        return hash.toByteArray()
    }

    /**
     * Calculates the FNV-1a hash, then XOR folds to achieve the desired length if the length
     * parameter is not one of {32, 64, 128, 256, 512, 1024}. Hash lengths longer than 1024
     * bits are not supported. Note that hash lengths which are not a multiple of 8 will
     * result in a byte array with some number (8 - (length mod 8)) of leading zeros.
     *
     * @param inp the byte array to be hashed
     * @param length the desired length (in bits) of the hash
     * @return the hash result
     * @throws UnsupportedOperationException length is less than 16 or more than 1024
     */
    @Throws(UnsupportedOperationException::class)
    fun fnv1a(inp: ByteArray, length: Int): ByteArray {
        var hash: BigInteger

        val (basis, prime, mod, foldingNeeded) = getParameters(length)
        hash = fnv1a_noXor(inp,basis,prime,mod)
        if(foldingNeeded) {
            hash = xorFold(hash, length)
        }
        // Return the byte array, note that it is always 1 bit longer than requested
        return hash.toByteArray()
    }

    data class Parameters(
        val basis: BigInteger,
        val prime: BigInteger,
        val mod: BigInteger,
        val foldNeeded: Boolean,
    )

    private fun getParameters(length: Int): Parameters  =
        when {
            length < 16 || length > 1024 ->
                throw UnsupportedOperationException("length must be between 16 and 1024, inclusive; received $length")
            length <= 32 -> Parameters(FNV_32_BASIS, FNV_32_PRIME, FNV_32_MOD,length < 32)
            length <= 64 -> Parameters(FNV_64_BASIS, FNV_64_PRIME, FNV_64_MOD, length < 64)
            length <= 128 -> Parameters(FNV_128_BASIS, FNV_128_PRIME, FNV_128_MOD, length < 128)
            length <= 256-> Parameters(FNV_256_BASIS, FNV_256_PRIME, FNV_256_MOD, length < 256)
            length <= 512 -> Parameters(FNV_512_BASIS, FNV_512_PRIME, FNV_512_MOD, length < 512)
            else -> Parameters(FNV_1024_BASIS, FNV_1024_PRIME, FNV_1024_MOD, length < 1024)
        }

    /**
     * Calculates the FNV-1 hash with no XOR folding.
     *
     * @param inp the byte array to be hashed
     * @param basis the FNV basis to use
     * @param prime the FNV prime to use
     * @param mod the FNV modulo to use
     * @return the hash result
     */
    private fun fnv1_noXor(
        inp: ByteArray, basis: BigInteger, prime: BigInteger,
        mod: BigInteger
    ): BigInteger {
        var digest = basis
        for (b: Byte in inp) {
            digest = digest.multiply(prime).mod(mod)
            digest = digest.xor(BigInteger.valueOf((b.toInt() and FNV_XOR).toLong()))
        }
        return digest
    }

    /**
     * Calculates the FNV-1a hash with no XOR folding.
     *
     * @param inp the byte array to be hashed
     * @param basis the FNV basis to use
     * @param prime the FNV prime to use
     * @param mod the FNV modulo to use
     * @return the hash result
     */
    private fun fnv1a_noXor(
        inp: ByteArray, basis: BigInteger, prime: BigInteger,
        mod: BigInteger
    ): BigInteger {
        var digest = basis
        for (b: Byte in inp) {
            digest = digest.xor(BigInteger.valueOf((b.toInt() and FNV_XOR).toLong()))
            digest = digest.multiply(prime).mod(mod)
        }
        return digest
    }

    /**
     * [XOR-folds](https://tools.ietf.org/html/draft-eastlake-fnv-12#section-3) a
     * BigInteger from one length down to another.
     *
     * @param inp the BigInteger to fold
     * @param k the required length (in bits) of the returned value
     * @return the result of the xor fold
     */
    private fun xorFold(inp: BigInteger, k: Int): BigInteger {
        val andme = BigInteger("2").pow(k).add(BigInteger("-1"))
        return (inp.xor(inp.shiftRight(k))).and(andme)
    }
}
