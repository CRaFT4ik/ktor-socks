package de.torsm.socks.client

import de.torsm.socks.protocol.SocksProtocolException
import de.torsm.socks.protocol.SocksUdpHeader
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.channels.AsynchronousCloseException
import java.nio.channels.ClosedByInterruptException

/**
 * A [DatagramSocket] shell that transparently wraps RFC 1928 UDP ASSOCIATE relay framing.
 *
 * All reads and writes are delegated to [delegate] (the real bound UDP socket); this class
 * does NOT inherit its I/O - it extends [DatagramSocket] with a null address so the JDK
 * treats it as an unbound shell and never opens a second OS socket.
 *
 * Lifecycle: the [tcpControl] socket must stay open for the duration of the relay.
 * [close] tears down TCP first (signals relay termination to the server), then UDP.
 *
 * @param delegate the bound local UDP socket through which datagrams flow.
 * @param relayEndpoint address:port of the SOCKS5 relay assigned by the proxy.
 * @param tcpControl TCP control connection that must remain open while the relay is active.
 * @param destination the remote IP this socket communicates with through the relay.
 *   Normalized on construction to strip IPv4-mapped-IPv6.
 */
public class Socks5UdpAssociateSocket internal constructor(
    private val delegate: DatagramSocket,
    private val relayEndpoint: InetSocketAddress,
    private val tcpControl: Socket,
    destination: InetAddress,
) : DatagramSocket(null as SocketAddress?) {

    // NF-7: strip IPv4-mapped-IPv6 (::ffff:a.b.c.d -> Inet4Address) via raw address bytes.
    private val destination: InetAddress = InetAddress.getByAddress(destination.address)

    /** Exposed for tests only - not part of public API. */
    internal val relayEndpointForTest: InetSocketAddress get() = relayEndpoint

    /** Exposed for tests only - not part of public API. */
    internal val tcpControlForTest: Socket get() = tcpControl

    private val log = LoggerFactory.getLogger(javaClass)

    @Volatile private var lastParseErrorLogNs: Long = 0L
    private val parseErrorLogRateLimitNs: Long = 5_000_000_000L

    // Scratch buffer for the raw OS receive. Using a dedicated buffer prevents the OS from
    // truncating the incoming datagram to the caller's (possibly offset-constrained) buffer size,
    // which is required for the D-S4 bounds check to work correctly.
    private val scratchBuf: ByteArray = ByteArray(65_507)

    // --- DatagramSocket delegation ---

    override fun getLocalAddress(): InetAddress = delegate.localAddress
    override fun getLocalPort(): Int = delegate.localPort
    override fun getLocalSocketAddress(): InetSocketAddress = delegate.localSocketAddress as InetSocketAddress
    override fun getReceiveBufferSize(): Int = delegate.receiveBufferSize
    override fun isClosed(): Boolean = delegate.isClosed
    override fun getSoTimeout(): Int = delegate.soTimeout
    override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }

    /**
     * Wraps [p] in a RFC 1928 section 7 header and sends the datagram to [relayEndpoint].
     *
     * @param p datagram to send; [DatagramPacket.getAddress] must equal [destination].
     * @throws IllegalStateException if the destination address does not match [destination].
     */
    override fun send(p: DatagramPacket) {
        if (p.address != destination) {
            throw IllegalStateException(
                "SOCKS5 send: address mismatch, expected $destination, got ${p.address}"
            )
        }
        val dst = InetSocketAddress(p.address, p.port)
        val payload = p.data.copyOfRange(p.offset, p.offset + p.length)
        val wrapped = SocksUdpHeader.wrap(dst, payload)
        delegate.send(DatagramPacket(wrapped, wrapped.size, relayEndpoint))
    }

    /**
     * Receives and unwraps the next valid RFC 1928 section 7 datagram, enforcing
     * source-address validation and budget-based timeout.
     *
     * Datagrams from unknown sources, fragmented datagrams (FRAG != 0), and
     * structurally malformed headers are silently discarded (up to 16 discards before
     * [SocketTimeoutException] is thrown, to bound resource use under FRAG-flood or spoofing).
     *
     * After unwrapping, rewrites [p.address][DatagramPacket.getAddress] and
     * [p.port][DatagramPacket.getPort] to the DST from the header so the caller
     * sees the original sender address, not the relay address.
     *
     * @param p buffer into which the payload is copied.
     * @throws SocketTimeoutException if the configured timeout expires or 16 discards occur.
     * @throws SocketException if the payload does not fit in the available buffer space.
     */
    override fun receive(p: DatagramPacket) {
        val budgetMs = delegate.soTimeout.toLong()
        val deadlineNs = if (budgetMs == 0L) Long.MAX_VALUE else System.nanoTime() + budgetMs * 1_000_000L
        var discards = 0
        while (true) {
            if (discards >= 16) {
                throw SocketTimeoutException("SOCKS5 receive: 16 discards, likely FRAG flood or spoof")
            }

            // NF-6: check deadline BEFORE calling setSoTimeout so a zero-budget path
            // never blocks even for 1 ms.
            if (deadlineNs != Long.MAX_VALUE) {
                val remainingMs = (deadlineNs - System.nanoTime()) / 1_000_000L
                if (remainingMs <= 0L) {
                    throw SocketTimeoutException("SOCKS5 receive: budget exhausted")
                }
                delegate.soTimeout = remainingMs.toInt().coerceAtLeast(1)
            }

            // Use scratchBuf so the OS delivers the full datagram regardless of caller's offset.
            val raw = DatagramPacket(scratchBuf, scratchBuf.size)
            try {
                delegate.receive(raw)
            } catch (e: SocketException) { throw e }
              catch (e: SocketTimeoutException) { throw e }
              catch (e: AsynchronousCloseException) { throw e }
              catch (e: ClosedByInterruptException) { throw e }

            // B-F5: drop datagrams not from the relay.
            if (raw.address != relayEndpoint.address || raw.port != relayEndpoint.port) {
                discards++; continue
            }

            // Parse RFC 1928 section 7 header.
            val parsed = try {
                SocksUdpHeader.parse(raw.data, raw.length)
            } catch (e: SocksProtocolException) {
                val now = System.nanoTime()
                if (now - lastParseErrorLogNs >= parseErrorLogRateLimitNs) {
                    lastParseErrorLogNs = now
                    log.debug("SOCKS5 receive: malformed section-7 header ({})", e.javaClass.simpleName)
                }
                discards++; continue
            }

            val dst = parsed.destination
            if (dst == null) {
                // DOMAIN inbound - server should never emit DOMAIN; treat as malformed.
                discards++; continue
            }

            // D-S4: bounds check before writing into caller's buffer.
            if (parsed.payload.size > p.data.size - p.offset) {
                throw SocketException(
                    "SOCKS5 receive: buffer too small: need ${parsed.payload.size} bytes at offset ${p.offset}, buf.size=${p.data.size}"
                )
            }

            parsed.payload.copyInto(p.data, p.offset)
            p.length = parsed.payload.size
            // A-F1: rewrite address+port so the caller sees the original sender, not the relay.
            p.address = dst.address
            p.port = dst.port
            return
        }
    }

    /**
     * Closes the relay. TCP control is closed first to signal termination to the proxy,
     * then the UDP socket, then the super-class shell.
     */
    override fun close() {
        runCatching { tcpControl.close() }
        runCatching { delegate.close() }
        super.close()
    }
}
