package de.torsm.socks.protocol

public enum class SOCKSVersion(
    public val code: Byte,
    public val replyVersion: Byte,
    public val successCode: Byte,
    public val networkUnreachableCode: Byte,
    public val unreachableHostCode: Byte,
    public val connectionRefusedCode: Byte,
) {
    SOCKS4(
        code = 4,
        replyVersion = 0,
        successCode = 90,
        networkUnreachableCode = 91,
        unreachableHostCode = 91,
        connectionRefusedCode = 91,
    ),
    SOCKS5(
        code = 5,
        replyVersion = 5,
        successCode = 0,
        networkUnreachableCode = 3,
        unreachableHostCode = 4,
        connectionRefusedCode = 5,
    );

    public companion object {
        public fun byCode(code: Byte): SOCKSVersion = values().firstOrNull { it.code == code }
            ?: throw SocksProtocolException.MalformedHeader("Invalid SOCKS version: $code")
    }
}
