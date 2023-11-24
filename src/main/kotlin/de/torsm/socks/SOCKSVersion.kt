package de.torsm.socks

public enum class SOCKSVersion(
    public val code: Byte,
    public val replyVersion: Byte,
    public val successCode: Byte,
    public val unreachableHostCode: Byte,
    public val connectionRefusedCode: Byte
) {
    SOCKS4(4, replyVersion = 0, successCode = 90, unreachableHostCode = 91, connectionRefusedCode = 91),
    SOCKS5(5, replyVersion = 5, successCode = 0, unreachableHostCode = 4, connectionRefusedCode = 5);

    public companion object {
        public fun byCode(code: Byte): SOCKSVersion = values().find { it.code == code }
            ?: throw SOCKSException("Invalid SOCKS version: $code")
    }
}
