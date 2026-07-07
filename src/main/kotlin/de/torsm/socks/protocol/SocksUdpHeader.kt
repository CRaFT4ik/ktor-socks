package de.torsm.socks.protocol

import java.net.InetSocketAddress

/**
 * RFC 1928 section 7 UDP request header codec.
 *
 * Encode path emits FRAG=0 and RSV=0x0000. Decode path accepts any RSV but
 * throws [SocksProtocolException.FragmentationNotSupported] on FRAG != 0.
 *
 * DOMAIN decoding returns the unresolved name. Callers must use an async DNS
 * resolver with an upper timeout, not blocking JDK getByName.
 */
public object SocksUdpHeader {

    /**
     * @property destination set for IPv4/IPv6; null for DOMAIN.
     * @property hostName set for DOMAIN; null for IP variants.
     * @property port big-endian port from the header.
     * @property payload datagram contents without the header.
     */
    public data class Parsed(
        val destination: InetSocketAddress?,
        val hostName: String?,
        val port: Int,
        val payload: ByteArray,
    )

    /** Assemble a section 7 datagram for an IPv4/IPv6 target. */
    public fun wrap(destination: InetSocketAddress, payload: ByteArray): ByteArray {
        val addr = destination.address
            ?: throw IllegalArgumentException("destination must be resolved: $destination")
        val addrPortBlock = AddressCodec.writeToByteArray(addr, destination.port)
        val out = ByteArray(3 + addrPortBlock.size + payload.size)
        addrPortBlock.copyInto(out, destinationOffset = 3)
        payload.copyInto(out, destinationOffset = 3 + addrPortBlock.size)
        return out
    }

    /** Assemble a section 7 datagram for a DOMAIN target. */
    public fun wrapDomain(host: String, port: Int, payload: ByteArray): ByteArray {
        val block = AddressCodec.writeDomainToByteArray(host, port)
        val out = ByteArray(3 + block.size + payload.size)
        block.copyInto(out, destinationOffset = 3)
        payload.copyInto(out, destinationOffset = 3 + block.size)
        return out
    }

    /** Parse a section 7 datagram. */
    public fun parse(buf: ByteArray, len: Int): Parsed {
        if (len < 4) throw SocksProtocolException.MalformedHeader("truncated udp header len=$len")
        if (buf[2] != 0x00.toByte()) {
            throw SocksProtocolException.FragmentationNotSupported("FRAG=${buf[2]}")
        }
        val addrOffset = 3
        val addrLen = len - addrOffset
        val parsed = AddressCodec.readGeneric(buf, addrOffset, addrLen)
        val payloadOffset = addrOffset + parsed.consumed
        val payload = buf.copyOfRange(payloadOffset, len)
        return if (parsed.address != null) {
            Parsed(InetSocketAddress(parsed.address, parsed.port), null, parsed.port, payload)
        } else {
            Parsed(null, parsed.host, parsed.port, payload)
        }
    }
}
