package de.torsm.socks.client

import de.torsm.socks.protocol.SocksReplyCode
import java.net.SocketException

/**
 * Base class for all client-side SOCKS5 errors.
 *
 * Extends [SocketException] so callers that catch IOException also catch these.
 *
 * @param message human-readable description.
 * @param retryable true when the caller may reconnect and retry; false when the
 *   failure is structural (misconfiguration, wrong proxy, auth rejected).
 * @param cause wrapped lower-level cause, if any.
 */
public open class SocksClientException internal constructor(
    message: String,
    public val retryable: Boolean,
    cause: Throwable? = null,
) : SocketException(message) {
    init { if (cause != null) initCause(cause) }

    /** TCP connection to the proxy host failed (DNS, refused, timeout, etc.). */
    public class ProxyUnreachable(cause: Throwable) :
        SocksClientException("SOCKS5 proxy unreachable: ${cause.message}", retryable = true, cause = cause)

    /** TCP control channel closed unexpectedly after the session started. */
    public class ProxyTcpClosed(cause: Throwable) :
        SocksClientException("SOCKS5 TCP-control closed mid-session", retryable = true, cause = cause)

    /**
     * The server replied with a VER byte other than 0x05 during method selection.
     *
     * @param actualVer raw byte received.
     */
    public class NotSocks5Proxy(actualVer: Byte) :
        SocksClientException("Not a SOCKS5 proxy: VER=0x%02X".format(actualVer.toInt() and 0xFF), retryable = false)

    /** Server returned 0xFF (no acceptable method) during method negotiation. */
    public class NoSharedMethod :
        SocksClientException("SOCKS5 no acceptable method (server returned 0xFF)", retryable = false)

    /** Server rejected RFC 1929 username/password sub-negotiation (STATUS != 0). */
    public class AuthFailed :
        SocksClientException("SOCKS5 RFC 1929 auth rejected (STATUS != 0)", retryable = false)

    /**
     * The server sent a structurally invalid response (wrong VER, unexpected field, etc.).
     *
     * @param message description of what was wrong.
     */
    public class ProtocolViolation(message: String) :
        SocksClientException("SOCKS5 protocol violation: $message", retryable = false)

    /** Server returned REP=0x01 (general failure) - transient, worth retrying. */
    public class RelayReplyGeneralFailure : SocksClientException(msgFor(SocksReplyCode.GENERAL_FAILURE), retryable = true)

    /** Server returned REP=0x03 (network unreachable) - transient, worth retrying. */
    public class RelayReplyNetworkUnreachable : SocksClientException(msgFor(SocksReplyCode.NETWORK_UNREACHABLE), retryable = true)

    /** Server returned REP=0x04 (host unreachable) - transient, worth retrying. */
    public class RelayReplyHostUnreachable : SocksClientException(msgFor(SocksReplyCode.HOST_UNREACHABLE), retryable = true)

    /** Server returned REP=0x05 (connection refused) - transient, worth retrying. */
    public class RelayReplyConnectionRefused : SocksClientException(msgFor(SocksReplyCode.CONNECTION_REFUSED), retryable = true)

    /** Server returned REP=0x06 (TTL expired) - transient, worth retrying. */
    public class RelayReplyTtlExpired : SocksClientException(msgFor(SocksReplyCode.TTL_EXPIRED), retryable = true)

    /** Server returned REP=0x02 (connection not allowed by ruleset) - policy reject, not retryable. */
    public class RelayReplyConnectionNotAllowed : SocksClientException(msgFor(SocksReplyCode.CONNECTION_NOT_ALLOWED), retryable = false)

    /** Server returned REP=0x07 (command not supported) - structural, not retryable. */
    public class RelayReplyCommandNotSupported : SocksClientException(msgFor(SocksReplyCode.COMMAND_NOT_SUPPORTED), retryable = false)

    /** Server returned REP=0x08 (address type not supported) - structural, not retryable. */
    public class RelayReplyAddressTypeNotSupported : SocksClientException(msgFor(SocksReplyCode.ADDRESS_TYPE_NOT_SUPPORTED), retryable = false)

    /**
     * Server returned an unassigned or reserved reply code.
     *
     * @param raw the raw byte from the wire.
     */
    public class RelayReplyUnknown(raw: Byte) :
        SocksClientException("SOCKS5 relay reply 0x%02X (reserved/unassigned reply code)".format(raw.toInt() and 0xFF), retryable = false)

    public companion object {
        internal fun msgFor(code: SocksReplyCode): String =
            "SOCKS5 relay reply 0x%02X (${code.name})".format(code.code.toInt() and 0xFF)

        /**
         * Map a [SocksReplyCode] to the appropriate [SocksClientException] subclass.
         *
         * @param code must not be [SocksReplyCode.SUCCEEDED].
         * @return the matching exception; [RelayReplyUnknown] for unassigned codes.
         * @throws IllegalStateException if [code] is SUCCEEDED.
         */
        public fun forReply(code: SocksReplyCode): SocksClientException = when (code) {
            SocksReplyCode.SUCCEEDED -> error("SUCCEEDED must not be wrapped as exception")
            SocksReplyCode.GENERAL_FAILURE -> RelayReplyGeneralFailure()
            SocksReplyCode.NETWORK_UNREACHABLE -> RelayReplyNetworkUnreachable()
            SocksReplyCode.HOST_UNREACHABLE -> RelayReplyHostUnreachable()
            SocksReplyCode.CONNECTION_REFUSED -> RelayReplyConnectionRefused()
            SocksReplyCode.TTL_EXPIRED -> RelayReplyTtlExpired()
            SocksReplyCode.CONNECTION_NOT_ALLOWED -> RelayReplyConnectionNotAllowed()
            SocksReplyCode.COMMAND_NOT_SUPPORTED -> RelayReplyCommandNotSupported()
            SocksReplyCode.ADDRESS_TYPE_NOT_SUPPORTED -> RelayReplyAddressTypeNotSupported()
            is SocksReplyCode.Unknown -> RelayReplyUnknown(code.raw)
        }
    }
}
