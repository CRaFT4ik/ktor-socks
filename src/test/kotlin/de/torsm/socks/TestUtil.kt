@file:Suppress("JAVA_MODULE_DOES_NOT_EXPORT_PACKAGE")
package de.torsm.socks

import io.ktor.network.sockets.*
import java.net.InetAddress
import java.net.Proxy
import java.net.Socket
import kotlin.test.assertEquals


val proxyServer = InetSocketAddress(InetAddress.getLocalHost().hostName, 1080)
val proxyServerJava = proxyServer.toJavaInetAddress()

val mockServer = InetSocketAddress(InetAddress.getLocalHost().hostName, 8080)
val mockServerJava = mockServer.toJavaInetAddress()

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
