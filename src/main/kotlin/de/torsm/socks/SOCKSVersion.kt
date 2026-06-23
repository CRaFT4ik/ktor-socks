package de.torsm.socks

public enum class SOCKSVersion(
    public val code: Byte,
    public val replyVersion: Byte,
    public val successCode: Byte,
    public val networkUnreachableCode: Byte,
    public val unreachableHostCode: Byte,
    public val connectionRefusedCode: Byte
) {
    // SOCKS4 uses a single failure code (91) for all error conditions
    SOCKS4(
        code = 4,
        replyVersion = 0,
        successCode = 90,
        networkUnreachableCode = 91,
        unreachableHostCode = 91,
        connectionRefusedCode = 91
    ),
    // SOCKS5 distinguishes network/host/refused per RFC 1928 §6
    SOCKS5(
        code = 5,
        replyVersion = 5,
        successCode = 0,
        networkUnreachableCode = 3,
        unreachableHostCode = 4,
        connectionRefusedCode = 5
    );

    public companion object {
        public fun byCode(code: Byte): SOCKSVersion = values().find { it.code == code }
            ?: throw SOCKSException("Invalid SOCKS version: $code")
    }
}
