package de.torsm.socks.protocol

public enum class SOCKSAddressType(public val code: Byte) {
    IPV4(0x01.toByte()),
    HOSTNAME(0x03.toByte()),
    IPV6(0x04.toByte());

    public companion object {
        public fun byCode(code: Byte): SOCKSAddressType = values().firstOrNull { it.code == code }
            ?: throw SocksProtocolException.UnsupportedAtype("Invalid ATYP: $code")
    }
}
