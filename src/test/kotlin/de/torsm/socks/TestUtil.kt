@file:Suppress("JAVA_MODULE_DOES_NOT_EXPORT_PACKAGE")
package de.torsm.socks

import io.ktor.network.sockets.*
import java.net.InetAddress
import java.net.Proxy
import java.net.Socket
import kotlin.test.assertEquals


/** Actual proxy server address, assigned by [MockServers] after binding on an ephemeral port. */
val proxyServer: InetSocketAddress get() = MockServers.proxyAddress
val proxyServerJava: java.net.InetSocketAddress get() = proxyServer.toJavaAddress() as java.net.InetSocketAddress

/** Actual echo/ping-pong server address, assigned by [MockServers] after binding. */
val mockServer: InetSocketAddress get() = MockServers.mockAddress
val mockServerJava: java.net.InetSocketAddress get() = mockServer.toJavaAddress() as java.net.InetSocketAddress

fun createClientSocket(socksVersion: Int): Socket {
    System.setProperty("socksProxyVersion", socksVersion.toString())
    val proxy = Proxy(Proxy.Type.SOCKS, proxyServerJava)
    return Socket(proxy)
}

fun Socket.ping() {
    getOutputStream().bufferedWriter().run {
        write("ping\n")
        flush()
    }
}

fun Socket.assertPong() {
    getInputStream().bufferedReader().run {
        assertEquals("pong", readLine())
    }
}
