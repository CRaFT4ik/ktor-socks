package de.torsm.socks

import de.torsm.socks.server.UsernamePasswordAuthentication
import de.torsm.socks.server.addAuthenticationMethod
import de.torsm.socks.server.socksServer
import de.torsm.socks.server.useWithChannels
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import org.junit.jupiter.api.extension.*
import java.lang.Short.toUnsignedInt
import java.lang.reflect.Method
import java.net.Authenticator
import java.net.Inet4Address
import java.net.PasswordAuthentication
import java.util.concurrent.atomic.AtomicReference

annotation class AllowSOCKS4
annotation class ClientCredentials(val username: String, val password: String)
annotation class ServerCredentials(val username: String, val password: String)

class MockServers : InvocationInterceptor, BeforeAllCallback, AfterAllCallback {
    lateinit var job: Job

    companion object {
        /**
         * Populated in [beforeAll] after the proxy and ping-pong servers bind to ephemeral ports.
         * Tests read these via the properties in TestUtil.kt.
         */
        val proxyAddressRef = AtomicReference<InetSocketAddress>()
        val mockAddressRef = AtomicReference<InetSocketAddress>()

        val proxyAddress: InetSocketAddress
            get() = proxyAddressRef.get() ?: error("MockServers not initialised")
        val mockAddress: InetSocketAddress
            get() = mockAddressRef.get() ?: error("MockServers not initialised")
    }

    override fun beforeAll(context: ExtensionContext) {
        val mutex = Mutex(locked = true)
        job = GlobalScope.launch(Dispatchers.IO) {
            launch {
                launchProxyServer(context)
                launchPingPongServer(mutex)
            }
        }
        runBlocking { mutex.lock() }
    }

    override fun afterAll(context: ExtensionContext) {
        runBlocking { job.cancelAndJoin() }
    }

    override fun interceptTestMethod(
        invocation: InvocationInterceptor.Invocation<Void>,
        invocationContext: ReflectiveInvocationContext<Method>,
        extensionContext: ExtensionContext
    ) {
        extensionContext.requiredTestMethod.getAnnotation(ClientCredentials::class.java)?.let { credentials ->
            Authenticator.setDefault(object : Authenticator() {
                override fun getPasswordAuthentication() =
                    PasswordAuthentication(credentials.username, credentials.password.toCharArray())
            })
        }

        try {
            invocation.proceed()
        } finally {
            Authenticator.setDefault(null)
        }
    }

    private fun CoroutineScope.launchProxyServer(context: ExtensionContext) {
        val localHost = java.net.InetAddress.getLocalHost().hostAddress
        val server = socksServer {
            // Port 0 lets the OS pick a free ephemeral port.
            networkAddress = InetSocketAddress(localHost, 0)
            allowSOCKS4 = context.requiredTestClass.isAnnotationPresent(AllowSOCKS4::class.java)

            context.requiredTestClass.getAnnotation(ServerCredentials::class.java)?.let { credentials ->
                addAuthenticationMethod(object : UsernamePasswordAuthentication() {
                    override fun verify(username: String, password: String) =
                        username == credentials.username && password == credentials.password
                })
            }
        }
        server.start()
        // SOCKSServer.boundAddress is set synchronously inside start() before returning.
        proxyAddressRef.set(server.boundAddress)
    }

    private suspend fun launchPingPongServer(mutex: Mutex) {
        val selector = ActorSelectorManager(Dispatchers.IO)
        val socketBuilder = aSocket(selector).tcp()
        val localHost = java.net.InetAddress.getLocalHost().hostAddress
        // Bind on all interfaces so the proxy can reach us via 127.0.0.1 OR the LAN IP.
        // Port 0 lets the OS pick a free ephemeral port.
        val serverSocket = socketBuilder.bind(InetSocketAddress("0.0.0.0", 0))
        val boundPort = (serverSocket.localAddress as InetSocketAddress).port
        // Advertise the LAN IP so the SOCKS proxy can reach us by hostname ("localhost" resolves
        // to 127.0.0.1 on the proxy side, which is also covered by 0.0.0.0 binding).
        mockAddressRef.set(InetSocketAddress(localHost, boundPort))

        try {
            mutex.unlock()
            while (true) {
                val client = serverSocket.accept()
                client.useWithChannels(true) { _, reader, writer ->
                    val line = reader.readUTF8Line()
                    if (line == "ping") {
                        writer.writeStringUtf8("pong\n")
                    } else if (line == "bound") {
                        val port = toUnsignedInt(reader.readShort())
                        val ip = ByteArray(4)
                        reader.readFully(ip)
                        val address = InetSocketAddress(Inet4Address.getByAddress(ip).hostAddress, port)
                        socketBuilder.connect(address).useWithChannels { _, r, w ->
                            if (r.readUTF8Line() == "ping") {
                                w.writeStringUtf8("pong\n")
                            }
                        }
                    }
                }
            }
        } finally {
            selector.close()
            serverSocket.close()
        }
    }
}
