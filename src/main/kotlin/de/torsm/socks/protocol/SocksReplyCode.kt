package de.torsm.socks.protocol

/**
 * RFC 1928 section 6 reply code. All 9 defined values plus [Unknown] for 0x09..0xFF
 * so the decode path does not throw on an unrecognised proxy reply.
 * Retryable vs fatal classification is in [SocksClientException] (client package).
 */
public sealed class SocksReplyCode(
    public val code: Byte,
    public val name: String,
) {
    public object SUCCEEDED : SocksReplyCode(0x00.toByte(), "SUCCEEDED")
    public object GENERAL_FAILURE : SocksReplyCode(0x01.toByte(), "GENERAL_FAILURE")
    public object CONNECTION_NOT_ALLOWED : SocksReplyCode(0x02.toByte(), "CONNECTION_NOT_ALLOWED")
    public object NETWORK_UNREACHABLE : SocksReplyCode(0x03.toByte(), "NETWORK_UNREACHABLE")
    public object HOST_UNREACHABLE : SocksReplyCode(0x04.toByte(), "HOST_UNREACHABLE")
    public object CONNECTION_REFUSED : SocksReplyCode(0x05.toByte(), "CONNECTION_REFUSED")
    public object TTL_EXPIRED : SocksReplyCode(0x06.toByte(), "TTL_EXPIRED")
    public object COMMAND_NOT_SUPPORTED : SocksReplyCode(0x07.toByte(), "COMMAND_NOT_SUPPORTED")
    public object ADDRESS_TYPE_NOT_SUPPORTED : SocksReplyCode(0x08.toByte(), "ADDRESS_TYPE_NOT_SUPPORTED")
    public class Unknown(public val raw: Byte) :
        SocksReplyCode(raw, "UNKNOWN(0x%02X)".format(raw.toInt() and 0xFF))

    public companion object {
        public fun of(code: Byte): SocksReplyCode = when (code) {
            0x00.toByte() -> SUCCEEDED
            0x01.toByte() -> GENERAL_FAILURE
            0x02.toByte() -> CONNECTION_NOT_ALLOWED
            0x03.toByte() -> NETWORK_UNREACHABLE
            0x04.toByte() -> HOST_UNREACHABLE
            0x05.toByte() -> CONNECTION_REFUSED
            0x06.toByte() -> TTL_EXPIRED
            0x07.toByte() -> COMMAND_NOT_SUPPORTED
            0x08.toByte() -> ADDRESS_TYPE_NOT_SUPPORTED
            else -> Unknown(code)
        }
    }
}
