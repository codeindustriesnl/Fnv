import net.orangeflows.common.util.Fnv

fun main(args: Array<String>) {
    println(Fnv.fnv1("Hello World!".toByteArray(), 119).decodeToString())
}
