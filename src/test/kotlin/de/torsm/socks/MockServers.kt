package de.torsm.socks

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

annotation class AllowSOCKS4
annotation class ClientCredentials(val username: String, val password: String)
annotation class ServerCredentials(val username: String, val password: String)

class MockServers : InvocationInterceptor, BeforeAllCallback, AfterAllCallback {
    lateinit var job: Job

    override fun beforeAll(context: ExtensionContext) {
        val mutex = Mutex(locked = true)
        job = GlobalScope.launch(Dispatchers.IO) {
            launch {
                launchProxyServer(context)
                launchPingPongServer(mutex)
            }
        }
        runBlocking {
            mutex.lock()
        }
    }

    override fun afterAll(context: ExtensionContext) {
        runBlocking {
            job.cancelAndJoin()
        }
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


    private fun CoroutineScope.launchProxyServer(context: ExtensionContext) = socksServer {
        networkAddress = proxyServer
        allowSOCKS4 = context.requiredTestClass.isAnnotationPresent(AllowSOCKS4::class.java)

        context.requiredTestClass.getAnnotation(ServerCredentials::class.java)?.let { credentials ->
            addAuthenticationMethod(object : UsernamePasswordAuthentication() {
                override fun verify(username: String, password: String) =
                    username == credentials.username && password == credentials.password
            })
        }
    }.start()

    private suspend fun launchPingPongServer(mutex: Mutex) {
        val socketBuilder = aSocket(ActorSelectorManager(Dispatchers.IO)).tcp()

        socketBuilder.bind(port = mockServer.port).use { serverSocket ->
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
        }
    }
}
