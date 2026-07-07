package de.torsm.socks.server

import de.torsm.socks.protocol.SOCKSCommand
import de.torsm.socks.protocol.SocksReplyCode
import de.torsm.socks.protocol.SocksUdpHeader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class SocksUdpRelayEchoTest {

    private val loopback: InetAddress = InetAddress.getLoopbackAddress()

    @Test
    fun `round-trip via SOCKS5 UDP ASSOCIATE echoes payload`() = runBlocking {
        val echoSocket = DatagramSocket(0, loopback)
        Thread({
            val buf = ByteArray(65_535)
            while (!echoSocket.isClosed) {
                val pkt = DatagramPacket(buf, buf.size)
                try { echoSocket.receive(pkt) } catch (_: Exception) { return@Thread }
                echoSocket.send(DatagramPacket(pkt.data, pkt.length, pkt.address, pkt.port))
            }
        }, "echo-target").apply { isDaemon = true; start() }
        val echoAddr = InetSocketAddress(loopback, echoSocket.localPort)

        val cfg = SOCKSConfigBuilder().apply {
            networkAddress = io.ktor.network.sockets.InetSocketAddress(loopback.hostAddress, 0)
            commands = setOf(SOCKSCommand.CONNECT, SOCKSCommand.UDP_ASSOCIATE)
            allowSOCKS4 = false
        }.build()
        val serverParentJob = Job()
        val server = SOCKSServer(cfg, Dispatchers.IO + serverParentJob)
        launch(Dispatchers.IO) { server.start() }
        val serverPort = awaitBoundPort(server)

        val tcp = Socket().apply { connect(InetSocketAddress(loopback, serverPort), 2000) }
        val din = DataInputStream(tcp.getInputStream())
        val dout = DataOutputStream(tcp.getOutputStream())
        dout.write(byteArrayOf(0x05.toByte(), 0x01.toByte(), 0x00.toByte()))
        dout.flush()
        val greeting = ByteArray(2).also { din.readFully(it) }
        assertEquals(0x05.toByte(), greeting[0])
        assertEquals(0x00.toByte(), greeting[1])

        val udpClient = DatagramSocket(0, loopback)
        val clientAddr = udpClient.localAddress.address
        val clientPort = udpClient.localPort
        val assocReq = ByteArray(10).also {
            it[0] = 0x05.toByte()
            it[1] = SOCKSCommand.UDP_ASSOCIATE.code
            it[2] = 0x00.toByte()
            it[3] = 0x01.toByte()
            clientAddr.copyInto(it, 4)
            it[8] = (clientPort ushr 8 and 0xFF).toByte()
            it[9] = (clientPort and 0xFF).toByte()
        }
        dout.write(assocReq); dout.flush()

        val head = ByteArray(4).also { din.readFully(it) }
        assertEquals(0x05.toByte(), head[0])
        assertEquals(SocksReplyCode.SUCCEEDED.code, head[1])
        assertEquals(0x01.toByte(), head[3])
        val bndAddrBytes = ByteArray(4).also { din.readFully(it) }
        val bndPort = (din.readUnsignedByte() shl 8) or din.readUnsignedByte()
        val bndAddr = InetAddress.getByAddress(bndAddrBytes)

        val payload = "hello relay".toByteArray()
        val wrapped = SocksUdpHeader.wrap(echoAddr, payload)
        udpClient.send(DatagramPacket(wrapped, wrapped.size, bndAddr, bndPort))

        val reply = DatagramPacket(ByteArray(65_535), 65_535)
        udpClient.soTimeout = 3000
        udpClient.receive(reply)
        val parsed = SocksUdpHeader.parse(reply.data, reply.length)
        assertContentEquals(payload, parsed.payload)
        assertEquals(echoAddr, parsed.destination)

        tcp.close()
        Thread.sleep(200)
        echoSocket.close()
        udpClient.close()
        // SEV-1-A: poll until server socket is released instead of just join()
        serverParentJob.cancel()
        var waited = 0
        while (server.boundPortOrNull() != null && waited < 100) {
            delay(50)
            waited++
        }
    }

    private suspend fun awaitBoundPort(s: SOCKSServer): Int {
        for (i in 0 until 100) {
            val p = s.boundPortOrNull()
            if (p != null) return p
            delay(20)
        }
        error("relay did not bind within 2s")
    }
}
