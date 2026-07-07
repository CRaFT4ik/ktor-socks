package de.torsm.socks.server

import de.torsm.socks.protocol.SOCKSAddressType
import de.torsm.socks.protocol.SOCKSAddressType.*
import de.torsm.socks.protocol.SOCKSCommand
import de.torsm.socks.protocol.SOCKSCommand.*
import de.torsm.socks.protocol.SOCKSVersion
import de.torsm.socks.protocol.SOCKSVersion.SOCKS4
import de.torsm.socks.protocol.SOCKSVersion.SOCKS5
import de.torsm.socks.protocol.SocksProtocolException
import de.torsm.socks.protocol.SocksReplyCode
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory
import java.lang.Byte.toUnsignedInt
import java.lang.Short.toUnsignedInt
import java.net.ConnectException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NoRouteToHostException
import java.net.UnknownHostException

@Suppress("BlockingMethodInNonBlockingContext")
public open class SOCKSHandshake(
    private val reader: ByteReadChannel,
    private val writer: ByteWriteChannel,
    private val config: SOCKSConfig,
    private val selector: SelectorManager
) {
    public lateinit var selectedVersion: SOCKSVersion; protected set
    public lateinit var hostSocket: Socket; private set

    private val log = LoggerFactory.getLogger(javaClass)

    public open suspend fun negotiate() {
        negotiateAuthorize()
        negotiateHandleRequest()
    }

    protected suspend fun negotiateAuthorize() {
        selectedVersion = reader.readVersion()
        when (selectedVersion) {
            SOCKS4 -> {
                if (!config.allowSOCKS4) {
                    sendFullReply(SOCKS4_REJECTED)
                    throw SOCKSException("SOCKS4 connection not allowed")
                }
            }
            SOCKS5 -> {
                handleAuthentication()
                // read version of SOCKS request
                check(reader.readVersion() == selectedVersion) { "Inconsistent SOCKS versions" }
            }
        }
    }

    protected suspend fun negotiateHandleRequest() {
        val request = receiveRequest()

        when (request.command) {
            CONNECT -> connect(request)
            BIND -> bind(request)
            UDP_ASSOCIATE -> {
                check(selectedVersion == SOCKS5) { "SOCKS4 does not support $UDP_ASSOCIATE" }
                if (SOCKSCommand.UDP_ASSOCIATE !in config.commands) {
                    sendFullReply(SOCKS5_COMMAND_NOT_SUPPORTED)
                    throw SOCKSException("Unsupported command: $UDP_ASSOCIATE")
                }
                val relayReq = buildRelayRequestFrom(request)
                SocksUdpRelay(this, relayReq, config, selector).run()
            }
        }
    }

    private suspend fun receiveRequest(): SOCKSRequest {
        val command: SOCKSCommand
        val address: InetAddress
        val port: Short

        when (selectedVersion) {
            SOCKS4 -> {
                command = reader.readCommand()
                port = reader.readShort()
                val ip = reader.readAddress()
                reader.readNullTerminatedString() // ignoring USERID field

                address = if (ip.isSOCKS4a) {
                    resolveHostnameOffDefault(reader.readNullTerminatedString())
                } else {
                    ip
                }
            }
            SOCKS5 -> {
                command = reader.readCommand()
                reader.readByte() // reserved (RSV) field
                address = reader.readAddress()
                port = reader.readShort()
            }
        }

        return SOCKSRequest(command, address, toUnsignedInt(port))
    }

    private suspend fun handleAuthentication() {
        val methodsCount = toUnsignedInt(reader.readByte())
        val clientMethods = List(methodsCount) { toUnsignedInt(reader.readByte()) }
        val commonMethod = config.authenticationMethods.firstOrNull { it.code in clientMethods }

        if (commonMethod == null) {
            // RFC 1928 section 3: reply X'FF' means no acceptable method; client MUST close.
            sendPartialReply(SOCKS5_NO_ACCEPTABLE_METHODS)
            throw SOCKSException("No common authentication method found")
        } else {
            sendPartialReply(commonMethod.code.toByte())
            commonMethod.negotiate(reader, writer)
        }
    }

    private suspend fun connect(request: SOCKSRequest) {
        // Pass the IP literal of the already-resolved InetAddress; no further DNS round trip is
        // implied. The HOSTNAME branch resolved the name asynchronously via [AsyncDnsResolver],
        // so request.destinationAddress is the chosen IP at this point.
        val host = InetSocketAddress(request.destinationAddress.hostAddress, request.port)
        hostSocket = try {
            withTimeout(config.connectTimeoutMillis) {
                aSocket(selector).tcp().connect(host)
            }
        } catch (e: ConnectException) {
            // RFC 1928 section 6: X'05' = Connection refused (SOCKS5 only; SOCKS4 uses generic failure)
            sendFullReply(selectedVersion.connectionRefusedCode)
            throw SOCKSException("Connection refused by host: $host", e)
        } catch (e: NoRouteToHostException) {
            // RFC 1928 section 6: X'03' = Network unreachable (SOCKS5 only; SOCKS4 uses generic failure)
            sendFullReply(selectedVersion.networkUnreachableCode)
            throw SOCKSException("No route to host: $host", e)
        } catch (e: Throwable) {
            // RFC 1928 section 6: X'04' = Host unreachable (general fallback)
            sendFullReply(selectedVersion.unreachableHostCode)
            throw SOCKSException("Unreachable host: $host", e)
        }

        try {
            if (log.isDebugEnabled) log.debug("Connected to {}", request.destinationAddress.toSocketString(host.port))
            sendFullReply(selectedVersion.successCode, hostSocket.localAddress as InetSocketAddress)
        } catch (e: Throwable) {
            hostSocket.close()
            throw e
        }
    }

    private suspend fun bind(request: SOCKSRequest) {
        hostSocket = coroutineScope {
            val address = config.networkAddress.withPort(0)
            aSocket(selector).tcp().bind(address).use { serverSocket ->
                val socketJob = async {
                    try {
                        withTimeout(config.connectTimeoutMillis) {
                            serverSocket.accept()
                        }
                    } catch (e: Throwable) {
                        sendFullReply(selectedVersion.unreachableHostCode)
                        throw SOCKSException("Host (${request.destinationAddress}) didn't connect to bound socket (${serverSocket.localAddress})", e)
                    }
                }
                sendFullReply(selectedVersion.successCode, serverSocket.localAddress as InetSocketAddress)
                socketJob.await()
            }
        }

        val hostAddress = hostSocket.remoteAddress as InetSocketAddress
        // Extract the java.net.InetAddress from the Ktor InetSocketAddress for comparison
        val connectingInetAddress = (hostAddress.toJavaAddress() as java.net.InetSocketAddress).address

        if (connectingInetAddress != request.destinationAddress) {
            sendFullReply(selectedVersion.connectionRefusedCode)
            hostSocket.close()
            throw SOCKSException("Incoming host address ($hostAddress) did not match requested host (${request.destinationAddress})")
        }

        try {
            log.debug("Host was bound: {}", hostAddress)
            sendFullReply(selectedVersion.successCode, hostAddress)
        } catch (e: Exception) {
            hostSocket.close()
            throw e
        }
    }

    private suspend fun sendPartialReply(code: Byte, writeAdditionalData: suspend BytePacketBuilder.() -> Unit = {}) {
        writer.writePacket {
            writeByte(selectedVersion.replyVersion)
            writeByte(code)
            writeAdditionalData()
        }
        writer.flush()
    }

    private suspend fun sendFullReply(code: Byte, address: InetSocketAddress = emptyAddress) {
        sendPartialReply(code) {
            if (selectedVersion == SOCKS5) writeByte(SOCKS5_RESERVED)
            writeAddress(address)
        }
    }



    private suspend fun ByteReadChannel.readVersion(): SOCKSVersion {
        val versionNumber = readByte()
        return SOCKSVersion.byCode(versionNumber)
    }

    private suspend fun ByteReadChannel.readCommand(): SOCKSCommand {
        val code = readByte()
        return try {
            SOCKSCommand.byCode(code)
        } catch (e: SocksProtocolException.MalformedHeader) {
            // RFC 1928 section 6: X'07' = Command not supported (SOCKS5 only)
            if (selectedVersion == SOCKS5) sendFullReply(SOCKS5_COMMAND_NOT_SUPPORTED)
            throw e
        }
    }

    private suspend fun ByteReadChannel.readAddress(): InetAddress {
        val addressType = when (selectedVersion) {
            SOCKS4 -> IPV4
            SOCKS5 -> {
                val code = readByte()
                try {
                    SOCKSAddressType.byCode(code)
                } catch (e: SocksProtocolException.UnsupportedAtype) {
                    // RFC 1928 section 6: X'08' = Address type not supported
                    sendFullReply(SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED)
                    throw e
                }
            }
        }
        return when (addressType) {
            IPV4 -> {
                val data = readPacket(4)
                Inet4Address.getByAddress(data.readBytes())
            }
            IPV6 -> {
                val data = readPacket(16)
                Inet6Address.getByAddress(data.readBytes())
            }
            HOSTNAME -> {
                val size = toUnsignedInt(readByte())
                val data = readPacket(size)
                resolveHostnameOffDefault(data.readBytes().decodeToString())
            }
        }
    }

    // Non-blocking DNS resolve: dnsjava NIO races 1.1.1.1 vs 8.8.8.8 with a system fallback.
    // The caller thread is never pinned on a slow getaddrinfo; the longest a hung resolver can
    // hold the path is bounded by AsyncDnsResolver.DEFAULT_TIMEOUT_MILLIS. NXDOMAIN or total
    // resolver failure surfaces as UnknownHostException, which the upstream code paths already
    // treat as an unreachable host.
    private suspend fun resolveHostnameOffDefault(host: String): InetAddress = try {
        AsyncDnsResolver.shared.resolve(host)
    } catch (e: UnknownHostException) {
        throw e
    }

    private fun BytePacketBuilder.writeAddress(address: InetSocketAddress) {
        val port = address.port.toShort()
        val ip = address.toJavaInetAddress().address
        when (selectedVersion) {
            SOCKS4 -> {
                check(ip is Inet4Address || ip.isAnyLocalAddress) { "Expecting IPv4 address for SOCKS4" }
                writeShort(port)
                writeFully(ip.address, length = 4)
            }
            SOCKS5 -> {
                when (ip) {
                    is Inet4Address -> writeByte(IPV4.code)
                    is Inet6Address -> writeByte(IPV6.code)
                    else -> error("Unknown InetAddress type: ${ip.javaClass}")
                }
                writeFully(ip.address)
                writeShort(port)
            }
        }
    }

    private fun InetAddress.toSocketString(port: Int): String {
        val str = toString()
        val i = str.indexOf('/')
        val hostname = if (i != 0) str.substring(0, i) else null
        val ip = str.substring(i + 1, str.length)
        return buildString {
            append(hostname ?: ip).append(':').append(port)
            if (hostname != null) {
                append(" (").append(ip).append(':').append(port).append(")")
            }
        }
    }

    internal data class SOCKSRequest(
        val command: SOCKSCommand,
        val destinationAddress: InetAddress,
        val port: Int
    )

    /**
     * Hints provided by the client in the UDP ASSOCIATE request.
     * [expectedClientAddr] is null when the client sent 0.0.0.0 (first-learn mode).
     * [expectedClientPort] is the UDP port the client will send datagrams from (0 = any).
     */
    public data class RelayRequest(
        val expectedClientAddr: java.net.InetAddress?,
        val expectedClientPort: Int,
    )

    /** Builds a [RelayRequest] from the parsed SOCKS request for UDP ASSOCIATE. */
    internal fun buildRelayRequestFrom(request: SOCKSRequest): RelayRequest {
        val addr = if (request.destinationAddress.isAnyLocalAddress) null else request.destinationAddress
        return RelayRequest(addr, request.port)
    }

    /**
     * Sends a UDP ASSOCIATE reply using a [SocksReplyCode] and Java [bnd] socket address.
     * Bridges between the Java type carried by [SocksUdpRelay] and ktor's write path.
     */
    internal suspend fun sendUdpAssociateReply(code: SocksReplyCode, bnd: java.net.InetSocketAddress) {
        val ktorBnd = io.ktor.network.sockets.InetSocketAddress(bnd.address.hostAddress, bnd.port)
        sendFullReply(code.code, ktorBnd)
    }

    /**
     * Reads from the TCP control channel until EOF, error, or [idleTimeoutMs] elapses without a
     * byte arriving. A positive [idleTimeoutMs] causes the method to return when no byte arrives
     * within the window; zero means "wait forever for EOF or error".
     *
     * Per RFC 1928 section 6 the client MUST NOT send any data on the TCP control connection
     * after UDP ASSOCIATE succeeds, so any read will only ever see EOF or a broken-pipe error.
     * We still drain rather than just wait on EOF so that garbage bytes do not stall the teardown.
     */
    internal suspend fun awaitControlChannelClose(idleTimeoutMs: Long = 0L) {
        if (idleTimeoutMs > 0L) {
            while (true) {
                val b = try {
                    kotlinx.coroutines.withTimeoutOrNull(idleTimeoutMs) { reader.readByte() }
                } catch (e: kotlinx.coroutines.CancellationException) { throw e }
                  catch (_: Throwable) { return }
                if (b == null) return
            }
        } else {
            try {
                while (true) { reader.readByte() }
            } catch (e: kotlinx.coroutines.CancellationException) { throw e }
              catch (_: Throwable) { }
        }
    }

    /** Cancels the TCP control channel read side, triggering teardown of [awaitControlChannelClose]. */
    internal fun closeTcpControl() {
        runCatching {
            reader.cancel(kotlinx.coroutines.CancellationException("idleWatchdog tearing down TCP control"))
        }
    }
}

private const val SOCKS4_REJECTED = 91.toByte()
private const val SOCKS5_RESERVED = 0.toByte()

// RFC 1928 section 6 reply codes (SOCKS5)
internal const val SOCKS5_COMMAND_NOT_SUPPORTED = 7.toByte()
internal const val SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED = 8.toByte()

// RFC 1928 section 3, method negotiation
private const val SOCKS5_NO_ACCEPTABLE_METHODS = 0xFF.toByte()

private val emptyAddress = InetSocketAddress("0.0.0.0", 0)
