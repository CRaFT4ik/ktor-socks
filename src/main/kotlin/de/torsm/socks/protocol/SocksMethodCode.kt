package de.torsm.socks.protocol

/**
 * RFC 1928 section 3 method code. Faithful wire representation: [of] never throws on unknown
 * codes; client rejects anything other than NoAuth and UserPass before use.
 */
public sealed class SocksMethodCode(public open val code: Byte) {
    public object NoAuth : SocksMethodCode(0x00.toByte())
    public object GssApi : SocksMethodCode(0x01.toByte())
    public object UserPass : SocksMethodCode(0x02.toByte())
    public data class IanaAssigned(override val code: Byte) : SocksMethodCode(code)
    public data class Private(override val code: Byte) : SocksMethodCode(code)
    public object NoAcceptable : SocksMethodCode(0xFF.toByte())

    public companion object {
        public fun of(code: Byte): SocksMethodCode {
            val u = code.toInt() and 0xFF
            return when {
                u == 0x00 -> NoAuth
                u == 0x01 -> GssApi
                u == 0x02 -> UserPass
                u in 0x03..0x7F -> IanaAssigned(code)
                u in 0x80..0xFE -> Private(code)
                u == 0xFF -> NoAcceptable
                else -> error("unreachable byte range")
            }
        }
    }
}
