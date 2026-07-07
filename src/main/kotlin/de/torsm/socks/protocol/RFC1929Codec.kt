package de.torsm.socks.protocol

/**
 * RFC 1929 SOCKS5 Username/Password sub-negotiation.
 * ULEN and PLEN must be in the range 1..255 as RFC explicitly requires.
 */
public object RFC1929Codec {

    private const val VERSION: Byte = 0x01.toByte()

    public data class Decoded(val username: String, val password: String)

    public fun encodeRequest(username: String, password: String): ByteArray {
        val u = username.toByteArray(Charsets.UTF_8)
        val p = password.toByteArray(Charsets.UTF_8)
        require(u.size in 1..255) { "username length ${u.size} out of RFC 1929 range 1..255" }
        require(p.size in 1..255) { "password length ${p.size} out of RFC 1929 range 1..255" }
        val out = ByteArray(1 + 1 + u.size + 1 + p.size)
        out[0] = VERSION
        out[1] = u.size.toByte()
        u.copyInto(out, 2)
        out[2 + u.size] = p.size.toByte()
        p.copyInto(out, 3 + u.size)
        return out
    }

    public fun decodeRequest(buf: ByteArray): Decoded {
        if (buf.size < 2) throw SocksProtocolException.MalformedHeader("truncated RFC 1929 request")
        if (buf[0] != VERSION) throw SocksProtocolException.MalformedHeader("RFC 1929 VER=${buf[0]}")
        val ulen = buf[1].toInt() and 0xFF
        if (ulen == 0) throw SocksProtocolException.MalformedHeader("ULEN=0 (RFC 1929 requires 1..255)")
        if (buf.size < 2 + ulen + 1) throw SocksProtocolException.MalformedHeader("truncated UNAME")
        // Use String(ByteArray, Charset): Kotlin stdlib decodeToString() has no charset overload.
        val user = String(buf.copyOfRange(2, 2 + ulen), Charsets.UTF_8)
        val plen = buf[2 + ulen].toInt() and 0xFF
        if (plen == 0) throw SocksProtocolException.MalformedHeader("PLEN=0 (RFC 1929 requires 1..255)")
        if (buf.size < 2 + ulen + 1 + plen) throw SocksProtocolException.MalformedHeader("truncated PASSWD")
        val pass = String(buf.copyOfRange(3 + ulen, 3 + ulen + plen), Charsets.UTF_8)
        return Decoded(user, pass)
    }

    /** Returns true if STATUS==0x00, false otherwise. Throws on malformed input. */
    public fun parseResponse(buf: ByteArray): Boolean {
        if (buf.size < 2) throw SocksProtocolException.MalformedHeader("RFC 1929 response truncated")
        if (buf[0] != VERSION) throw SocksProtocolException.MalformedHeader("RFC 1929 response VER=0x${buf[0].toUByte().toString(16)}")
        return buf[1] == 0x00.toByte()
    }
}
