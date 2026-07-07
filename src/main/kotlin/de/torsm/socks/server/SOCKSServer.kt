package de.torsm.socks.server

import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import kotlin.coroutines.CoroutineContext

/**
 * Listens on a server socket and accepts clients that want to use the SOCKS protocol.
 *
 * This implementation uses ktor's suspending sockets which are based on coroutines.
 *
 * When accepting a SOCKS5 client, this implementation selects the _first_ element in the list of [config]'s
 * [authentication methods][SOCKSAuthenticationMethod] that the client supports.
 *
 * To create a [SOCKSServer], refer to the top level [socksServer] functions.
 */
public open class SOCKSServer(
    protected val config: SOCKSConfig,
    context: CoroutineContext
): CoroutineScope {
    private val log = LoggerFactory.getLogger(javaClass)

    private val exceptionHandler = CoroutineExceptionHandler { _, t -> log.trace(t.message, t) }

    override val coroutineContext: CoroutineContext =
        context + SupervisorJob(context.job) + CoroutineName("socks-server") + exceptionHandler

    protected val selector: SelectorManager = ActorSelectorManager(Dispatchers.IO)

    /**
     * The address this server is actually bound to after [start] has been called.
     * Useful when the server was configured with port 0 (ephemeral port assignment).
     */
    @Volatile
    public var boundAddress: InetSocketAddress = config.networkAddress
        private set

    /**
     * Returns the port this server is bound to, or null when not yet bound or when the port is 0
     * (which signals "not bound" before [start] assigns an ephemeral port).
     * Used by tests to poll for readiness instead of racing on [boundAddress].
     */
    internal fun boundPortOrNull(): Int? = boundAddress.port.takeIf { it != 0 }

    /**
     * Launches a coroutine that listens on the network address defined in [config] to accept clients, initiate
     * handshakes, and relay traffic between the client and the host server.
     *
     * This method returns after launching the coroutine, but can be wrapped in a [runBlocking] call to block the
     * thread if desired.
     */
    public fun start() {
        val serverSocket = aSocket(selector).tcp().bind(config.networkAddress)
        boundAddress = serverSocket.localAddress as InetSocketAddress
        log.info("Starting SOCKS proxy server on {}", boundAddress)

        launch {
            serverSocket.use {
                while (true) {
                    val clientSocket = serverSocket.accept()
                    val clientName = clientSocket.remoteAddress.toString()
                    log.debug("SOCKS client connected: {}", clientName)

                    launchClientJob(clientSocket).invokeOnCompletion {
                        log.debug("SOCKS client disconnected: {} (reason: {})", clientName, disconnectReason(it))
                    }
                }
            }
        }.invokeOnCompletion {
            selector.close()
        }
    }

    private fun launchClientJob(clientSocket: Socket) = launch {
        clientSocket.useWithChannels { _, reader, writer ->
            serveTheClient(clientSocket, reader, writer)
        }
    }

    protected open suspend fun serveTheClient(socket: Socket, reader: ByteReadChannel, writer: ByteWriteChannel) {
        val handshake = SOCKSHandshake(reader, writer, config, selector)
        handshake.negotiate()
        handshake.hostSocket.useWithChannels { _, hostReader, hostWriter ->
            coroutineScope {
                val proxy1 = relayApplicationData(reader, hostWriter)
                val proxy2 = relayApplicationData(hostReader, writer)
                cancelOnCompletion("Closed: no data to read", proxy1, proxy2)
            }
        }
    }

    private fun CoroutineScope.relayApplicationData(src: ByteReadChannel, dst: ByteWriteChannel): Job {
        return launch {
            try {
                src.joinTo(dst, false)
            } catch (ignored: Exception) {
                /* Exceptions while relaying channel traffic (due to closed sockets for example)
                 * are not exceptional and are considered the natural end of client/host communication */
            }
        }
    }

    private fun CoroutineScope.cancelOnCompletion(message: String, vararg tasks: Job) {
        tasks.forEach {
            it.invokeOnCompletion { t -> this@cancelOnCompletion.cancel(message, t) }
        }
    }

    /**
     * pick the most informative message from a completion throwable.
     *
     * inner coroutine machinery often surfaces generic strings like
     * "StandaloneCoroutine was cancelled" while the real reason sits on `cause`.
     * prefer the outer message when it carries content, otherwise walk to the
     * cause; fall back to "normally" when the client just closed cleanly.
     */
    private fun disconnectReason(t: Throwable?): String {
        if (t == null) return "normally"
        val own = t.message?.takeIf { it.isNotBlank() && !it.startsWith("StandaloneCoroutine") }
        if (own != null) return own
        val causeMsg = t.cause?.message?.takeIf { it.isNotBlank() }
        return causeMsg ?: t.message ?: t::class.java.simpleName
    }
}
