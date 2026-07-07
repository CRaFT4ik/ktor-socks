package de.torsm.socks.server

import de.torsm.socks.protocol.SocksProtocolException
import de.torsm.socks.protocol.SocksReplyCode
import de.torsm.socks.protocol.SocksUdpHeader
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.toJavaAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.concurrent.atomic.AtomicReference

/**
 * Implements the RFC 1928 UDP ASSOCIATE relay loop.
 *
 * Lifecycle: caller invokes [run], which opens two UDP sockets, sends the BND reply, then runs
 * three concurrent children inside a [coroutineScope]:
 *   - loopA: client-side socket, strips section-7 header, forwards payload to target.
 *   - loopB: target-side socket, wraps reply in section-7 header, forwards to client.
 *   - idleWatchdog: tears down when no client datagrams arrive for [SOCKSConfig.udpIdleAssociationTimeoutSeconds].
 *
 * The TCP control channel drives teardown: when the client closes it (or the idle watchdog fires),
 * [SOCKSHandshake.awaitControlChannelClose] returns and the coroutineScope cancels all children.
 * Both sockets are closed in the finally block under [NonCancellable] so they release even when
 * the parent coroutine is cancelled.
 *
 * @param handshake active handshake whose TCP control channel governs the relay lifetime.
 * @param request client hints from the UDP ASSOCIATE request (optional source-filter address/port).
 * @param config server config; supplies network address for BND reply and idle timeout.
 * @param selector ktor selector manager (unused in this blocking-socket implementation; kept for
 *   future non-blocking rewrite parity with the CONNECT path).
 */
internal class SocksUdpRelay(
    private val handshake: SOCKSHandshake,
    private val request: SOCKSHandshake.RelayRequest,
    private val config: SOCKSConfig,
    @Suppress("UnusedPrivateProperty")
    private val selector: SelectorManager,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    // Relay socket: clients send wrapped datagrams here; the server strips the header and forwards.
    private val relaySocket: DatagramSocket = DatagramSocket(
        0,
        (config.networkAddress.toJavaAddress() as java.net.InetSocketAddress).address,
    )

    // Outbound socket: raw datagrams go to the actual target, replies come back here.
    private val outboundSocket: DatagramSocket = DatagramSocket()

    // Pinned source address of the SOCKS client. Null until the first valid datagram arrives
    // (first-learn mode when the client sent 0.0.0.0 in the UDP ASSOCIATE request).
    private val expectedClientSrc = AtomicReference<InetSocketAddress?>(
        request.expectedClientAddr?.let { InetSocketAddress(it, request.expectedClientPort) }
    )

    @Volatile private var lastClientActivityNs: Long = System.nanoTime()

    // Rate-limit the parse-error log to one line per 5 seconds so a flood of malformed datagrams
    // does not saturate the log file.
    @Volatile private var lastLoopAParseErrorLogNs: Long = 0L

    /**
     * Sends the BND reply and runs the relay until the TCP control channel closes or the idle
     * watchdog fires. Both sockets are closed on exit regardless of the exit path.
     */
    internal suspend fun run() {
        val bnd = relaySocket.localSocketAddress as InetSocketAddress
        // When the relay socket is bound to 0.0.0.0, report the server's configured address
        // instead so the client knows where to send datagrams.
        val bndReply = if (bnd.address.isAnyLocalAddress) {
            InetSocketAddress(
                (config.networkAddress.toJavaAddress() as java.net.InetSocketAddress).address,
                bnd.port,
            )
        } else bnd
        handshake.sendUdpAssociateReply(SocksReplyCode.SUCCEEDED, bndReply)

        try {
            coroutineScope {
                launch(Dispatchers.IO) { loopA() }
                launch(Dispatchers.IO) { loopB() }
                launch { idleWatchdog() }
                // Block until the TCP control channel closes (or the idle watchdog cancels this).
                try {
                    val idleMs = config.udpIdleAssociationTimeoutSeconds * 1_000L
                    handshake.awaitControlChannelClose(idleTimeoutMs = idleMs)
                } finally {
                    // Cancel the IO loops by closing their sockets.
                    withContext(NonCancellable) {
                        runCatching { relaySocket.close() }
                        runCatching { outboundSocket.close() }
                    }
                }
            }
        } finally {
            // Double-close guard: coroutineScope cancel path may not have hit the inner finally.
            runCatching { relaySocket.close() }
            runCatching { outboundSocket.close() }
        }
    }

    /**
     * Client-facing receive loop. Reads section-7 wrapped datagrams from the relay socket,
     * validates the source, strips the header, and forwards the payload to the target.
     */
    private suspend fun loopA() {
        val buf = ByteArray(65_535)
        while (!relaySocket.isClosed) {
            val pkt = DatagramPacket(buf, buf.size)
            try {
                withContext(Dispatchers.IO) { relaySocket.receive(pkt) }
            } catch (e: SocketException) {
                if (relaySocket.isClosed) return else throw e
            }
            val src = InetSocketAddress(pkt.address, pkt.port)

            // Source validation: pin the first sender when the client sent 0.0.0.0.
            val expected = expectedClientSrc.get()
            if (expected == null) {
                if (!expectedClientSrc.compareAndSet(null, src)) {
                    // CAS race: another thread pinned first; drop this datagram.
                    log.debug("loopA: first-packet CAS race lost, dropping src")
                    continue
                }
            } else if (src != expected) {
                log.debug("loopA: dropping datagram from wrong src (expected pinned)")
                continue
            }
            lastClientActivityNs = System.nanoTime()

            val parsed = try {
                SocksUdpHeader.parse(pkt.data, pkt.length)
            } catch (e: SocksProtocolException) {
                val now = System.nanoTime()
                if (now - lastLoopAParseErrorLogNs > 5_000_000_000L) {
                    lastLoopAParseErrorLogNs = now
                    log.debug("loopA: malformed section 7 header ({})", e.javaClass.simpleName)
                }
                continue
            }

            val dst: InetSocketAddress = when {
                parsed.destination != null -> parsed.destination
                parsed.hostName != null -> {
                    // SEV-2-F: catch UnknownHostException in addition to timeout null.
                    val addr = try {
                        withTimeoutOrNull(2_000L) { AsyncDnsResolver.shared.resolve(parsed.hostName) }
                    } catch (_: java.net.UnknownHostException) { null }
                    if (addr == null) {
                        log.debug("loopA: DNS-fail for redacted host, dropping")
                        continue
                    } else InetSocketAddress(addr, parsed.port)
                }
                else -> continue
            }
            withContext(Dispatchers.IO) {
                outboundSocket.send(DatagramPacket(parsed.payload, parsed.payload.size, dst))
            }
        }
    }

    /**
     * Target-facing receive loop. Reads raw datagrams from the outbound socket, wraps them in a
     * section-7 header, and forwards to the pinned client address.
     */
    private suspend fun loopB() {
        val buf = ByteArray(65_535)
        while (!outboundSocket.isClosed) {
            val pkt = DatagramPacket(buf, buf.size)
            try {
                withContext(Dispatchers.IO) { outboundSocket.receive(pkt) }
            } catch (e: SocketException) {
                if (outboundSocket.isClosed) return else throw e
            }
            val client = expectedClientSrc.get()
            if (client == null) {
                log.debug("loopB: no client pinned yet, dropping inbound target packet")
                continue
            }
            val wrapped = SocksUdpHeader.wrap(
                InetSocketAddress(pkt.address, pkt.port),
                pkt.data.copyOfRange(0, pkt.length),
            )
            withContext(Dispatchers.IO) {
                relaySocket.send(DatagramPacket(wrapped, wrapped.size, client))
            }
        }
    }

    /**
     * Monitors client activity. Closes both sockets and the TCP control channel when no datagram
     * has arrived for [SOCKSConfig.udpIdleAssociationTimeoutSeconds] seconds. Exits immediately
     * when the budget is zero or when the relay socket is already closed.
     */
    private suspend fun idleWatchdog() {
        val budgetNs = config.udpIdleAssociationTimeoutSeconds * 1_000_000_000L
        if (budgetNs <= 0) return
        while (!relaySocket.isClosed) {
            val idle = System.nanoTime() - lastClientActivityNs
            if (idle >= budgetNs) {
                log.debug(
                    "idleWatchdog: tearing down association after {}s of silence",
                    config.udpIdleAssociationTimeoutSeconds,
                )
                withContext(NonCancellable) {
                    runCatching { relaySocket.close() }
                    runCatching { outboundSocket.close() }
                    runCatching { handshake.closeTcpControl() }
                }
                return
            }
            delay((budgetNs - idle) / 1_000_000)
        }
    }
}
