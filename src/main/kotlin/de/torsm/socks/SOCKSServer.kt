package de.torsm.socks

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
     * Launches a coroutine that listens on the network address defined in [config] to accept clients, initiate
     * handshakes, and relay traffic between the client and the host server.
     *
     * This method returns after launching the coroutine, but can be wrapped in a [runBlocking] call to block the
     * thread if desired.
     */
    public fun start() {
        val serverSocket = aSocket(selector).tcp().bind(config.networkAddress)
        log.info("Starting SOCKS proxy server on {}", serverSocket.localAddress)

        launch {
            serverSocket.use {
                while (true) {
                    val clientSocket = serverSocket.accept()
                    val clientName = clientSocket.remoteAddress.toString()
                    log.debug("SOCKS client connected: {}", clientName)

                    launchClientJob(clientSocket).invokeOnCompletion {
                        log.debug("SOCKS client disconnected: {} (reason: {})", clientName, it?.message ?: "normally")
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
}
