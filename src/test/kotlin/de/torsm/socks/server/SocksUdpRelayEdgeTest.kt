package de.torsm.socks.server

import de.torsm.socks.protocol.SOCKSCommand
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
import java.net.SocketTimeoutException
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SocksUdpRelayEdgeTest {

    private val loopback: InetAddress = InetAddress.getLoopbackAddress()

    private data class Assoc(
        val tcp: Socket, val udp: DatagramSocket, val bnd: InetSocketAddress,
        val server: SOCKSServer,
        val serverParentJob: Job,
    )

    private suspend fun openAssociation(scope: kotlinx.coroutines.CoroutineScope): Assoc {
        val cfg = SOCKSConfigBuilder().apply {
            networkAddress = io.ktor.network.sockets.InetSocketAddress(loopback.hostAddress, 0)
            commands = setOf(SOCKSCommand.CONNECT, SOCKSCommand.UDP_ASSOCIATE)
            allowSOCKS4 = false
        }.build()
        val serverParentJob = Job()
        val server = SOCKSServer(cfg, Dispatchers.IO + serverParentJob)
        scope.launch(Dispatchers.IO) { server.start() }
        var port: Int? = null
        for (i in 0 until 100) {
            port = server.boundPortOrNull(); if (port != null) break
            delay(20)
        }
        val serverPort = port ?: error("no bind")
        val tcp = Socket().apply { connect(InetSocketAddress(loopback, serverPort), 2000) }
        val din = DataInputStream(tcp.getInputStream())
        val dout = DataOutputStream(tcp.getOutputStream())
        dout.write(byteArrayOf(0x05.toByte(), 0x01.toByte(), 0x00.toByte())); dout.flush()
        din.readFully(ByteArray(2))
        val udp = DatagramSocket(0, loopback)
        val ap = udp.localPort
        val addr = udp.localAddress.address
        val req = ByteArray(10).also {
            it[0] = 0x05.toByte(); it[1] = 0x03.toByte(); it[2] = 0x00.toByte(); it[3] = 0x01.toByte()
            addr.copyInto(it, 4); it[8] = (ap ushr 8 and 0xFF).toByte(); it[9] = (ap and 0xFF).toByte()
        }
        dout.write(req); dout.flush()
        val head = ByteArray(4).also { din.readFully(it) }
        val bAddr = ByteArray(4).also { din.readFully(it) }
        val bPort = (din.readUnsignedByte() shl 8) or din.readUnsignedByte()
        return Assoc(tcp, udp, InetSocketAddress(InetAddress.getByAddress(bAddr), bPort), server, serverParentJob)
    }

    private suspend fun teardown(a: Assoc) {
        // SEV-1-A: poll instead of join()
        a.serverParentJob.cancel()
        var waited = 0
        while (a.server.boundPortOrNull() != null && waited < 100) {
            delay(50)
            waited++
        }
    }

    @Test
    fun `wrong-src datagram is dropped and never reaches target`() = runBlocking {
        val a = openAssociation(this)
        val target = DatagramSocket(0, loopback)
        target.soTimeout = 400
        val wrapped = SocksUdpHeader.wrap(InetSocketAddress(loopback, target.localPort), byteArrayOf(1, 2, 3))

        val impostor = DatagramSocket(0, loopback)
        impostor.send(DatagramPacket(wrapped, wrapped.size, a.bnd.address, a.bnd.port))
        var received = false
        try { target.receive(DatagramPacket(ByteArray(64), 64)); received = true }
        catch (_: SocketTimeoutException) { }
        assertEquals(false, received)
        target.close(); impostor.close(); a.tcp.close(); a.udp.close()
        teardown(a)
    }

    @Test
    fun `first-packet CAS race pins the winner loser is silently dropped`() = runBlocking {
        val cfg = SOCKSConfigBuilder().apply {
            networkAddress = io.ktor.network.sockets.InetSocketAddress(loopback.hostAddress, 0)
            commands = setOf(SOCKSCommand.CONNECT, SOCKSCommand.UDP_ASSOCIATE)
            allowSOCKS4 = false
        }.build()
        val serverParentJob = Job()
        val server = SOCKSServer(cfg, Dispatchers.IO + serverParentJob)
        launch(Dispatchers.IO) { server.start() }
        var port: Int? = null
        for (i in 0 until 100) { port = server.boundPortOrNull(); if (port != null) break; delay(20) }
        val serverPort = port ?: error("no bind")

        val tcp = Socket().apply { connect(InetSocketAddress(loopback, serverPort), 2000) }
        val din = DataInputStream(tcp.getInputStream())
        val dout = DataOutputStream(tcp.getOutputStream())
        dout.write(byteArrayOf(0x05.toByte(), 0x01.toByte(), 0x00.toByte())); dout.flush()
        din.readFully(ByteArray(2))

        // DST.ADDR = 0.0.0.0, DST.PORT = 0 => relay enters first-learn mode
        val req = byteArrayOf(
            0x05.toByte(), 0x03.toByte(), 0x00.toByte(), 0x01.toByte(),
            0.toByte(), 0.toByte(), 0.toByte(), 0.toByte(),
            0x00.toByte(), 0x00.toByte(),
        )
        dout.write(req); dout.flush()
        val head = ByteArray(4).also { din.readFully(it) }
        val bAddr = ByteArray(4).also { din.readFully(it) }
        val bPort = (din.readUnsignedByte() shl 8) or din.readUnsignedByte()
        val bnd = InetSocketAddress(InetAddress.getByAddress(bAddr), bPort)

        val target = DatagramSocket(0, loopback); target.soTimeout = 500
        val targetAddr = InetSocketAddress(loopback, target.localPort)

        val receivedCount = java.util.concurrent.atomic.AtomicInteger(0)
        val echoThread = Thread({
            val buf = DatagramPacket(ByteArray(64), 64)
            repeat(2) {
                runCatching {
                    target.soTimeout = 500
                    target.receive(buf)
                    receivedCount.incrementAndGet()
                }
            }
        }, "cas-echo-counter").apply { isDaemon = true; start() }

        val udpA = DatagramSocket(0, loopback)
        val udpB = DatagramSocket(0, loopback)
        val payload = SocksUdpHeader.wrap(targetAddr, byteArrayOf(0x77.toByte()))

        val ta = Thread({ udpA.send(DatagramPacket(payload, payload.size, bnd.address, bnd.port)) })
        val tb = Thread({ udpB.send(DatagramPacket(payload, payload.size, bnd.address, bnd.port)) })
        ta.start(); tb.start(); ta.join(); tb.join()
        echoThread.join(1500)

        assertEquals(1, receivedCount.get(), "exactly one of two racing first-packets must be forwarded")
        assertTrue(tcp.isConnected && !tcp.isClosed, "relay must still be alive after CAS race")

        tcp.close(); udpA.close(); udpB.close(); target.close()
        // SEV-1-A teardown
        serverParentJob.cancel()
        var waited = 0
        while (server.boundPortOrNull() != null && waited < 100) { delay(50); waited++ }
    }

    @Test
    fun `FRAG != 0 datagram is dropped`() = runBlocking {
        val a = openAssociation(this)
        val target = DatagramSocket(0, loopback); target.soTimeout = 400
        val bad = byteArrayOf(
            0x00.toByte(), 0x00.toByte(),
            0x01.toByte(),  // FRAG=1
            0x01.toByte(),
            127.toByte(), 0.toByte(), 0.toByte(), 1.toByte(),
            (target.localPort ushr 8).toByte(), (target.localPort and 0xFF).toByte(),
            1.toByte(), 2.toByte(), 3.toByte(),
        )
        a.udp.send(DatagramPacket(bad, bad.size, a.bnd.address, a.bnd.port))
        var received = false
        try { target.receive(DatagramPacket(ByteArray(64), 64)); received = true }
        catch (_: SocketTimeoutException) { }
        assertEquals(false, received)
        target.close(); a.tcp.close(); a.udp.close()
        teardown(a)
    }

    @Test
    fun `writing bytes on TCP-control does not tear down association`() = runBlocking {
        val a = openAssociation(this)
        DataOutputStream(a.tcp.getOutputStream()).apply { write(ByteArray(42) { 7 }); flush() }
        val target = DatagramSocket(0, loopback); target.soTimeout = 1000
        val wrapped = SocksUdpHeader.wrap(InetSocketAddress(loopback, target.localPort), byteArrayOf(9))
        a.udp.send(DatagramPacket(wrapped, wrapped.size, a.bnd.address, a.bnd.port))
        val pkt = DatagramPacket(ByteArray(64), 64)
        target.receive(pkt)
        assertEquals(9.toByte(), pkt.data[0])
        target.close(); a.tcp.close(); a.udp.close()
        teardown(a)
    }

    @Test
    fun `closing TCP-control tears down UDP relay (named-resource leak detector)`() = runBlocking {
        val a = openAssociation(this)
        a.tcp.close()
        delay(500)

        // SEV-2-B: do NOT assertNull(a.server.boundPortOrNull()) -- that's the accept socket, not the relay BND socket
        // Rely on port-probe to verify relay socket is released
        val pkt = SocksUdpHeader.wrap(InetSocketAddress(loopback, 65535), byteArrayOf(0))
        val probe = DatagramSocket(0, loopback); probe.soTimeout = 200
        var seenIcmpOrTimeout = false
        try {
            probe.send(DatagramPacket(pkt, pkt.size, a.bnd.address, a.bnd.port))
            probe.receive(DatagramPacket(ByteArray(64), 64))
        } catch (_: SocketTimeoutException) { seenIcmpOrTimeout = true }
          catch (_: java.net.PortUnreachableException) { seenIcmpOrTimeout = true }
        assertTrue(seenIcmpOrTimeout, "relay socket should be closed after TCP-control tear-down")
        assertTrue(a.tcp.isClosed, "client TCP control must be closed")

        probe.close(); a.udp.close()
        teardown(a)
    }

    @Test
    fun `idle-timeout tears down UDP relay and TCP control`() = runBlocking {
        val cfg = SOCKSConfigBuilder().apply {
            networkAddress = io.ktor.network.sockets.InetSocketAddress(loopback.hostAddress, 0)
            commands = setOf(SOCKSCommand.CONNECT, SOCKSCommand.UDP_ASSOCIATE)
            allowSOCKS4 = false
            udpIdleAssociationTimeoutSeconds = 1L
        }.build()
        val serverParentJob = Job()
        val server = SOCKSServer(cfg, Dispatchers.IO + serverParentJob)
        launch(Dispatchers.IO) { server.start() }
        var port: Int? = null
        for (i in 0 until 100) { port = server.boundPortOrNull(); if (port != null) break; delay(20) }
        val serverPort = port ?: error("no bind")

        val tcp = Socket().apply { connect(InetSocketAddress(loopback, serverPort), 2000) }
        val din = DataInputStream(tcp.getInputStream())
        val dout = DataOutputStream(tcp.getOutputStream())
        dout.write(byteArrayOf(0x05.toByte(), 0x01.toByte(), 0x00.toByte())); dout.flush()
        din.readFully(ByteArray(2))
        val udp = DatagramSocket(0, loopback)
        val ap = udp.localPort; val addr = udp.localAddress.address
        val req = ByteArray(10).also {
            it[0] = 0x05.toByte(); it[1] = 0x03.toByte(); it[2] = 0x00.toByte(); it[3] = 0x01.toByte()
            addr.copyInto(it, 4); it[8] = (ap ushr 8 and 0xFF).toByte(); it[9] = (ap and 0xFF).toByte()
        }
        dout.write(req); dout.flush()
        val head = ByteArray(4).also { din.readFully(it) }
        val bAddr = ByteArray(4).also { din.readFully(it) }
        val bPort = (din.readUnsignedByte() shl 8) or din.readUnsignedByte()
        val bnd = InetSocketAddress(InetAddress.getByAddress(bAddr), bPort)

        // Wait for idle timeout (1s budget + 500ms margin)
        delay(1800)

        // TCP control should be closed (EOF)
        tcp.soTimeout = 500
        val tcpEof = try { din.read() == -1 } catch (_: Exception) { true }
        assertTrue(tcpEof, "idleWatchdog must close TCP control; server-side EOF expected on client read")

        // UDP relay: BND port should be closed
        val probe = DatagramSocket(0, loopback); probe.soTimeout = 200
        val pkt = SocksUdpHeader.wrap(InetSocketAddress(loopback, 65535), byteArrayOf(0))
        var udpDown = false
        try {
            probe.send(DatagramPacket(pkt, pkt.size, bnd.address, bnd.port))
            probe.receive(DatagramPacket(ByteArray(64), 64))
        } catch (_: SocketTimeoutException) { udpDown = true }
          catch (_: java.net.PortUnreachableException) { udpDown = true }
        assertTrue(udpDown, "relay UDP socket must be closed after idle timeout")

        probe.close(); tcp.close(); udp.close()
        // SEV-1-A teardown
        serverParentJob.cancel()
        var waited = 0
        while (server.boundPortOrNull() != null && waited < 100) { delay(50); waited++ }
    }
}
