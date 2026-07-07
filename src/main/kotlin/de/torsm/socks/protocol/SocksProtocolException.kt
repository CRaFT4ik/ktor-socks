package de.torsm.socks.protocol

/**
 * Decoding error for SOCKS wire format.
 *
 * @property replyCode the reply code the server must send back (RFC 1928 section 6).
 *   For client-side parse errors the value is [SocksReplyCode.GENERAL_FAILURE] as
 *   a placeholder; the client does not send a reply but the field remains non-null
 *   for uniform server-side serialisation.
 */
public open class SocksProtocolException(
    message: String,
    public val replyCode: SocksReplyCode = SocksReplyCode.GENERAL_FAILURE,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {

    /** RSV, FRAG, ATYP, ULEN, PLEN and length checks. */
    public class MalformedHeader(message: String, cause: Throwable? = null) :
        SocksProtocolException(message, SocksReplyCode.GENERAL_FAILURE, cause)

    /** ATYP not in {0x01, 0x03, 0x04}. Server replies 0x08. */
    public class UnsupportedAtype(message: String) :
        SocksProtocolException(message, SocksReplyCode.ADDRESS_TYPE_NOT_SUPPORTED)

    /** RFC 1928 section 7: receiver not supporting fragmentation MUST drop. */
    public class FragmentationNotSupported(message: String) :
        SocksProtocolException(message, SocksReplyCode.GENERAL_FAILURE)
}
