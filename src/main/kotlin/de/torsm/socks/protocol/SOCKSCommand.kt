package de.torsm.socks.protocol

public enum class SOCKSCommand(public val code: Byte) {
    CONNECT(0x01.toByte()),
    BIND(0x02.toByte()),
    UDP_ASSOCIATE(0x03.toByte());

    public companion object {
        public fun byCode(code: Byte): SOCKSCommand = values().firstOrNull { it.code == code }
            ?: throw SocksProtocolException.MalformedHeader("Invalid SOCKS command: $code")
    }
}
