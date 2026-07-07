package de.torsm.socks.client

import de.torsm.socks.protocol.SocksUdpHeader
import org.junit.jupiter.api.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for [Socks5UdpAssociateSocket].
 *
 * Each test creates a real loopback DatagramSocket as the "relay" sender and a
 * [Socks5UdpAssociateSocket] wrapping a local DatagramSocket as the delegate.
 * This exercises the full encode/decode path without a real SOCKS5 proxy.
 */
class Socks5UdpAssociateSocketTest {

    private val loopback: InetAddress = InetAddress.getLoopbackAddress()

    /**
     * Allocates a [DatagramSocket] bound to loopback at an ephemeral port.
     * Returns it as a relay endpoint.
     */
    private fun allocRelay(): DatagramSocket = DatagramSocket(0, loopback)

    /**
     * Builds a [Socks5UdpAssociateSocket] with [delegate] receiving from [relaySocket].
     *
     * [destination] defaults to loopback (port 4433) if not supplied.
     */
    private fun buildSock(
        delegate: DatagramSocket,
        relaySocket: DatagramSocket,
        destination: InetAddress = loopback,
    ): Socks5UdpAssociateSocket {
        val relayEndpoint = InetSocketAddress(loopback, relaySocket.localPort)
        val tcpControl = Socket() // never connected; used for isClosed check in close() test
        return Socks5UdpAssociateSocket(
            delegate = delegate,
            relayEndpoint = relayEndpoint,
            tcpControl = tcpControl,
            destination = destination,
        )
    }

    /**
     * Sends a wrapped IPv4 datagram from [sender] to [targetPort] on loopback.
     * [dstAddr] and [dstPort] go into the RFC 1928 section 7 header DST fields.
     */
    private fun sendWrapped(
        sender: DatagramSocket,
        targetPort: Int,
        payload: ByteArray,
        dstAddr: InetAddress = loopback,
        dstPort: Int = 4433,
    ) {
        val wrapped = SocksUdpHeader.wrap(InetSocketAddress(dstAddr, dstPort), payload)
        sender.send(DatagramPacket(wrapped, wrapped.size, loopback, targetPort))
    }

    // -------------------------------------------------------------------------
    // Test 1: receive rewrites address and port per A-F1
    // -------------------------------------------------------------------------

    @Test
    fun `receive rewrites packet address and port to parsed DST per A-F1`() {
        val relay = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay, loopback)
        sock.soTimeout = 3_000

        val payload = byteArrayOf(1, 2, 3, 4, 5)
        sendWrapped(relay, delegate.localPort, payload, dstAddr = loopback, dstPort = 4433)

        val buf = ByteArray(256)
        val pkt = DatagramPacket(buf, buf.size)
        sock.receive(pkt)

        assertEquals(loopback, pkt.address, "address must be DST from header")
        assertEquals(4433, pkt.port, "port must be DST.port from header")
        assertContentEquals(payload, buf.copyOf(pkt.length))

        sock.close(); relay.close()
    }

    // -------------------------------------------------------------------------
    // Test 2: receive drops datagrams from wrong source (B-F5)
    // -------------------------------------------------------------------------

    @Test
    fun `receive drops datagrams from wrong source B-F5`() {
        val relay = allocRelay()
        val impostor = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay)
        sock.soTimeout = 3_000

        val badPayload = byteArrayOf(0xFF.toByte())
        val goodPayload = byteArrayOf(0x77)

        // Impostor sends first - its address does not match the relayEndpoint.
        sendWrapped(impostor, delegate.localPort, badPayload)
        // Relay sends valid datagram second.
        sendWrapped(relay, delegate.localPort, goodPayload)

        val buf = ByteArray(256)
        val pkt = DatagramPacket(buf, buf.size)
        sock.receive(pkt)

        assertContentEquals(goodPayload, buf.copyOf(pkt.length), "impostor datagram must be dropped")

        sock.close(); relay.close(); impostor.close()
    }

    // -------------------------------------------------------------------------
    // Test 3: receive throws SocketTimeoutException after 16 FRAG discards (B-F4)
    // -------------------------------------------------------------------------

    @Test
    fun `receive throws SocketTimeoutException after 16 FRAG discards`() {
        val relay = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay)
        sock.soTimeout = 3_000

        // FRAG=1 datagrams - SocksUdpHeader.parse will throw FragmentationNotSupported.
        val fragDatagram = byteArrayOf(
            0x00, 0x00, // RSV
            0x01,       // FRAG = 1
            0x01,       // ATYP IPv4
            127, 0, 0, 1,
            0x11, 0x51, // port 4433
            0x42,       // payload byte
        )
        repeat(30) {
            relay.send(DatagramPacket(fragDatagram, fragDatagram.size, loopback, delegate.localPort))
        }

        assertFailsWith<SocketTimeoutException> {
            val buf = ByteArray(256)
            sock.receive(DatagramPacket(buf, buf.size))
        }

        sock.close(); relay.close()
    }

    // -------------------------------------------------------------------------
    // Test 4: close closes TCP-control first then UDP (A-F5)
    // -------------------------------------------------------------------------

    @Test
    fun `close closes TCP-control first and then UDP`() {
        val relay = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay)

        sock.close()

        assertTrue(sock.tcpControlForTest.isClosed, "TCP control must be closed")
        assertTrue(sock.isClosed, "delegate (and hence sock) must be closed")

        relay.close()
    }

    // -------------------------------------------------------------------------
    // Test 5: send throws IllegalStateException on address mismatch (FIX-1)
    // -------------------------------------------------------------------------

    @Test
    fun `send throws IllegalStateException on destination address mismatch`() {
        val relay = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay, destination = loopback)

        val wrongAddr = InetAddress.getByName("10.0.0.1")
        val pkt = DatagramPacket(byteArrayOf(1, 2, 3), 3, wrongAddr, 4433)

        assertFailsWith<IllegalStateException> {
            sock.send(pkt)
        }

        sock.close(); relay.close()
    }

    // -------------------------------------------------------------------------
    // Test 6: receive throws SocketException when buffer too small (D-S4)
    // Uses offset so available space = data.size - offset < payload.size
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Tests 7-9: IPv4-mapped-IPv6 normalization (FIX-4)
    // -------------------------------------------------------------------------

    @Test
    fun `IPv4-mapped-IPv6 normalizes to Inet4Address`() {
        val mapped = InetAddress.getByAddress(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF.toByte(), 0xFF.toByte(),
                192.toByte(), 168.toByte(), 1, 1)
        )
        val relay = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay, destination = mapped)

        assertFalse(sock.destinationForTest is Inet6Address, "should not remain Inet6Address after normalization")
        assertContentEquals(byteArrayOf(192.toByte(), 168.toByte(), 1, 1), sock.destinationForTest.address)

        sock.close(); relay.close()
    }

    @Test
    fun `plain IPv4 stays IPv4`() {
        val v4 = InetAddress.getByName("192.168.1.1")
        val relay = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay, destination = v4)

        assertTrue(sock.destinationForTest is Inet4Address, "plain IPv4 must remain Inet4Address")
        assertContentEquals(byteArrayOf(192.toByte(), 168.toByte(), 1, 1), sock.destinationForTest.address)

        sock.close(); relay.close()
    }

    @Test
    fun `plain IPv6 stays IPv6`() {
        val v6 = InetAddress.getByName("2001:db8::1")
        val relay = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay, destination = v6)

        assertTrue(sock.destinationForTest is Inet6Address, "plain IPv6 must remain Inet6Address")

        sock.close(); relay.close()
    }

    @Test
    fun `receive throws SocketException when receive buffer too small for payload D-S4`() {
        val relay = allocRelay()
        val delegate = DatagramSocket(0, loopback)
        val sock = buildSock(delegate, relay)
        sock.soTimeout = 3_000

        // Send a datagram with 20 bytes of payload.
        // Section-7 header (IPv4): RSV(2)+FRAG(1)+ATYP(1)+addr(4)+port(2) = 10 bytes
        // Total on the wire: 30 bytes.
        val payload = ByteArray(20) { it.toByte() }
        sendWrapped(relay, delegate.localPort, payload)

        // Use a 64-byte buffer but at offset 60: only 4 bytes available.
        // parsed.payload.size = 20, (64 - 60) = 4 => 20 > 4 => SocketException.
        val bigBuf = ByteArray(64)
        val pkt = DatagramPacket(bigBuf, 60, 4)

        assertFailsWith<SocketException> {
            sock.receive(pkt)
        }

        sock.close(); relay.close()
    }
}
