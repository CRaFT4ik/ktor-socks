package de.torsm.socks.protocol

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Shared codec for the {ATYP, ADDR, PORT} triple per RFC 1928 sections 4/5/7.
 *
 * DOMAIN decoding returns an unresolved name in [Parsed.host]: any DNS resolution
 * must be done by the caller via an async resolver, not blocking JDK getByName.
 */
internal object AddressCodec {

    /**
     * @property address set for IPv4/IPv6; null for DOMAIN.
     * @property host set for DOMAIN; null for IP variants.
     * @property port big-endian port.
     * @property consumed how many bytes the parser consumed starting from offset.
     */
    internal data class Parsed(
        val address: InetAddress?,
        val host: String?,
        val port: Int,
        val consumed: Int,
    )

    /** IPv4/IPv6 short form: (InetAddress, port, consumed); DOMAIN is an error here. */
    internal fun readIpFromByteArray(buf: ByteArray, offset: Int, length: Int): Triple<InetAddress, Int, Int> {
        val p = readGeneric(buf, offset, length)
        val addr = p.address
            ?: throw SocksProtocolException.MalformedHeader("expected IP ATYP, got DOMAIN host=${p.host}")
        return Triple(addr, p.port, p.consumed)
    }

    /** Full variant with DOMAIN support. */
    internal fun readGeneric(buf: ByteArray, offset: Int, length: Int): Parsed {
        if (length < 1) throw SocksProtocolException.MalformedHeader("empty address block")
        val atypRaw = buf[offset]
        return when (atypRaw) {
            SOCKSAddressType.IPV4.code -> {
                val needed = 1 + 4 + 2
                if (length < needed) throw SocksProtocolException.MalformedHeader("truncated IPv4 addr block, need=$needed got=$length")
                val ip = InetAddress.getByAddress(buf.copyOfRange(offset + 1, offset + 5)) as Inet4Address
                val port = ((buf[offset + 5].toInt() and 0xFF) shl 8) or (buf[offset + 6].toInt() and 0xFF)
                Parsed(ip, null, port, needed)
            }
            SOCKSAddressType.IPV6.code -> {
                val needed = 1 + 16 + 2
                if (length < needed) throw SocksProtocolException.MalformedHeader("truncated IPv6 addr block, need=$needed got=$length")
                val ip = InetAddress.getByAddress(buf.copyOfRange(offset + 1, offset + 17)) as Inet6Address
                val port = ((buf[offset + 17].toInt() and 0xFF) shl 8) or (buf[offset + 18].toInt() and 0xFF)
                Parsed(ip, null, port, needed)
            }
            SOCKSAddressType.HOSTNAME.code -> {
                if (length < 2) throw SocksProtocolException.MalformedHeader("truncated DOMAIN LEN")
                val nameLen = buf[offset + 1].toInt() and 0xFF
                val needed = 1 + 1 + nameLen + 2
                if (length < needed) throw SocksProtocolException.MalformedHeader("truncated DOMAIN body, need=$needed got=$length")
                // Use String(ByteArray, Charset): Kotlin stdlib decodeToString() has no charset overload.
                val host = String(buf.copyOfRange(offset + 2, offset + 2 + nameLen), Charsets.US_ASCII)
                val portOff = offset + 2 + nameLen
                val port = ((buf[portOff].toInt() and 0xFF) shl 8) or (buf[portOff + 1].toInt() and 0xFF)
                Parsed(null, host, port, needed)
            }
            else -> throw SocksProtocolException.UnsupportedAtype("unknown ATYP=$atypRaw")
        }
    }

    /** Serialize IPv4/IPv6 address + port into [ATYP][ADDR][PORT]. */
    internal fun writeToByteArray(address: InetAddress, port: Int): ByteArray {
        return when (address) {
            is Inet4Address -> ByteArray(1 + 4 + 2).also {
                it[0] = SOCKSAddressType.IPV4.code
                address.address.copyInto(it, 1)
                it[5] = (port ushr 8 and 0xFF).toByte()
                it[6] = (port and 0xFF).toByte()
            }
            is Inet6Address -> ByteArray(1 + 16 + 2).also {
                it[0] = SOCKSAddressType.IPV6.code
                address.address.copyInto(it, 1)
                it[17] = (port ushr 8 and 0xFF).toByte()
                it[18] = (port and 0xFF).toByte()
            }
            else -> throw IllegalArgumentException("Unknown InetAddress type: ${address.javaClass}")
        }
    }

    /** DOMAIN-variant write for server Loop A relay. */
    internal fun writeDomainToByteArray(host: String, port: Int): ByteArray {
        val name = host.toByteArray(Charsets.US_ASCII)
        require(name.size in 1..255) { "DOMAIN host length ${name.size} out of RFC 1928 range 1..255" }
        return ByteArray(1 + 1 + name.size + 2).also {
            it[0] = SOCKSAddressType.HOSTNAME.code
            it[1] = name.size.toByte()
            name.copyInto(it, 2)
            val portOff = 2 + name.size
            it[portOff] = (port ushr 8 and 0xFF).toByte()
            it[portOff + 1] = (port and 0xFF).toByte()
        }
    }
}
