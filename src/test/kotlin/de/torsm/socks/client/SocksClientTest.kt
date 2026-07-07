package de.torsm.socks.client

import de.torsm.socks.protocol.SocksReplyCode
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Unit tests for [SocksClient] using an in-process mock proxy.
 *
 * Each test spins up a loopback [ServerSocket], runs a mock-proxy thread that
 * reads the client request and writes a scripted response, then lets the client
 * connect to it. This avoids real network I/O while exercising the full handshake
 * and reply-parsing code paths.
 */
class SocksClientTest {

    private val loopback: InetAddress = InetAddress.getLoopbackAddress()

    /**
     * Runs [proxyScript] on a background thread that owns a [ServerSocket].
     * Returns the port the server is bound to.
     */
    private fun runMockProxy(proxyScript: (DataInputStream, DataOutputStream) -> Unit): Int {
        val server = ServerSocket(0, 1, loopback)
        Thread({
            try {
                server.accept().use { conn ->
                    val din = DataInputStream(conn.getInputStream())
                    val dout = DataOutputStream(conn.getOutputStream())
                    proxyScript(din, dout)
                    Thread.sleep(200) // ensure client reads full reply before close
                }
            } catch (_: Exception) {
            } finally {
                server.close()
            }
        }, "mock-proxy").apply { isDaemon = true; start() }
        return server.localPort
    }

    /** Builds a [SocksClient] pointing at the given loopback port, with custom [udpFactory]. */
    private fun client(
        port: Int,
        credentials: SocksCredentials? = null,
        udpFactory: (InetAddress) -> DatagramSocket = { DatagramSocket(0, loopback) },
    ): SocksClient = SocksClient(
        config = SocksClientConfig(
            proxyHost = loopback.hostAddress,
            proxyPort = port,
            credentials = credentials,
            connectTimeoutMillis = 3_000L,
            handshakeTimeoutMillis = 3_000L,
        ),
        udpBindFactory = udpFactory,
    )

    /**
     * Writes a successful ASSOCIATE reply with IPv4 BND.ADDR = loopback and BND.PORT = [port].
     * Reads and discards the ASSOCIATE request from the client.
     */
    private fun writeAssociateReply(din: DataInputStream, dout: DataOutputStream, bndPort: Int = 9999) {
        // consume the ASSOCIATE request: VER(1)+CMD(1)+RSV(1)+ATYP(1)+addr(4)+port(2) = 10 bytes
        din.readFully(ByteArray(10))
        val reply = byteArrayOf(
            0x05.toByte(),
            SocksReplyCode.SUCCEEDED.code,
            0x00.toByte(),
            0x01.toByte(), // IPv4
            127, 0, 0, 1,
            (bndPort ushr 8 and 0xFF).toByte(),
            (bndPort and 0xFF).toByte(),
        )
        dout.write(reply); dout.flush()
    }

    // -------------------------------------------------------------------------
    // Test 1: no credentials offers only NO_AUTH
    // -------------------------------------------------------------------------

    @Test
    fun `no credentials offers only NO_AUTH`() {
        var capturedOffer: ByteArray? = null
        val port = runMockProxy { din, dout ->
            // read greeting: VER(1) + NMETHODS(1) + METHODS(n)
            val ver = din.readByte()
            val n = din.readUnsignedByte()
            val methods = ByteArray(n).also { din.readFully(it) }
            capturedOffer = byteArrayOf(ver, n.toByte()) + methods
            // reply with NO_AUTH chosen
            dout.write(byteArrayOf(0x05.toByte(), 0x00.toByte())); dout.flush()
            // send ASSOCIATE reply
            writeAssociateReply(din, dout)
        }

        runBlocking {
            val sock = client(port).udpAssociate(loopback)
            sock.close()
        }

        val offer = capturedOffer!!
        assertEquals(1, offer[1].toInt() and 0xFF, "NMETHODS must be 1")
        assertEquals(0x00.toByte(), offer[2], "offered method must be NO_AUTH (0x00)")
    }

    // -------------------------------------------------------------------------
    // Test 2: credentials offers only USER_PASS
    // -------------------------------------------------------------------------

    @Test
    fun `credentials offers only USER_PASS`() {
        var capturedOffer: ByteArray? = null
        val port = runMockProxy { din, dout ->
            val ver = din.readByte()
            val n = din.readUnsignedByte()
            val methods = ByteArray(n).also { din.readFully(it) }
            capturedOffer = byteArrayOf(ver, n.toByte()) + methods
            // reply with USER_PASS chosen
            dout.write(byteArrayOf(0x05.toByte(), 0x02.toByte())); dout.flush()
            // RFC 1929 sub-negotiation: consume request, reply success
            din.readByte() // sub-negotiation VER (0x01)
            val ulen = din.readUnsignedByte()
            din.readFully(ByteArray(ulen))
            val plen = din.readUnsignedByte()
            din.readFully(ByteArray(plen))
            dout.write(byteArrayOf(0x01.toByte(), 0x00.toByte())); dout.flush()
            writeAssociateReply(din, dout)
        }

        val creds = SocksCredentials("user", "pass")
        runBlocking {
            val sock = client(port, credentials = creds).udpAssociate(loopback)
            sock.close()
        }

        val offer = capturedOffer!!
        assertEquals(1, offer[1].toInt() and 0xFF, "NMETHODS must be 1")
        assertEquals(0x02.toByte(), offer[2], "offered method must be USER_PASS (0x02)")
    }

    // -------------------------------------------------------------------------
    // Test 3: server selecting method not offered throws ProtocolViolation
    // -------------------------------------------------------------------------

    @Test
    fun `server selecting method not offered throws ProtocolViolation`() {
        val port = runMockProxy { din, dout ->
            // consume greeting
            din.readByte(); val n = din.readUnsignedByte(); din.readFully(ByteArray(n))
            // reply with USER_PASS (0x02) even though client offered only NO_AUTH (0x00)
            dout.write(byteArrayOf(0x05.toByte(), 0x02.toByte())); dout.flush()
        }

        // no credentials => client offers only NO_AUTH
        val ex = assertFailsWith<SocksClientException.ProtocolViolation> {
            runBlocking { client(port).udpAssociate(loopback) }
        }
        assertTrue(ex.message!!.contains("0x02"), "message should cite the offending method code")
    }

    // -------------------------------------------------------------------------
    // Test 4: VER != 5 in method-selection throws NotSocks5Proxy
    // -------------------------------------------------------------------------

    @Test
    fun `VER not 5 in method selection throws NotSocks5Proxy`() {
        val port = runMockProxy { din, dout ->
            din.readByte(); val n = din.readUnsignedByte(); din.readFully(ByteArray(n))
            dout.write(byteArrayOf(0x04.toByte(), 0x00.toByte())); dout.flush()
        }

        assertFailsWith<SocksClientException.NotSocks5Proxy> {
            runBlocking { client(port).udpAssociate(loopback) }
        }
    }

    // -------------------------------------------------------------------------
    // Test 5: NoAcceptable 0xFF from server throws NoSharedMethod
    // -------------------------------------------------------------------------

    @Test
    fun `NoAcceptable 0xFF from server throws NoSharedMethod`() {
        val port = runMockProxy { din, dout ->
            din.readByte(); val n = din.readUnsignedByte(); din.readFully(ByteArray(n))
            dout.write(byteArrayOf(0x05.toByte(), 0xFF.toByte())); dout.flush()
        }

        assertFailsWith<SocksClientException.NoSharedMethod> {
            runBlocking { client(port).udpAssociate(loopback) }
        }
    }

    // -------------------------------------------------------------------------
    // Test 6: REP != 0x00 in ASSOCIATE reply maps to RelayReplyHostUnreachable
    // -------------------------------------------------------------------------

    @Test
    fun `REP HOST_UNREACHABLE 0x04 in ASSOCIATE reply throws RelayReplyHostUnreachable`() {
        val port = runMockProxy { din, dout ->
            // consume greeting
            din.readByte(); val n = din.readUnsignedByte(); din.readFully(ByteArray(n))
            // reply NO_AUTH
            dout.write(byteArrayOf(0x05.toByte(), 0x00.toByte())); dout.flush()
            // consume ASSOCIATE request
            din.readFully(ByteArray(10))
            // reply HOST_UNREACHABLE (0x04)
            dout.write(byteArrayOf(
                0x05.toByte(),
                SocksReplyCode.HOST_UNREACHABLE.code,
                0x00.toByte(),
                0x01.toByte(),
                0, 0, 0, 0,
                0, 0,
            )); dout.flush()
        }

        assertFailsWith<SocksClientException.RelayReplyHostUnreachable> {
            runBlocking { client(port).udpAssociate(loopback) }
        }
    }

    // -------------------------------------------------------------------------
    // Test 7: IPv6 BND ADDR ATYP=0x04 parsed normally
    // -------------------------------------------------------------------------

    @Test
    fun `IPv6 BND ADDR ATYP 0x04 parsed normally`() {
        val ipv6Addr = Inet6Address.getByName("::1") as Inet6Address
        val bndPort = 7654
        val port = runMockProxy { din, dout ->
            din.readByte(); val n = din.readUnsignedByte(); din.readFully(ByteArray(n))
            dout.write(byteArrayOf(0x05.toByte(), 0x00.toByte())); dout.flush()
            // consume ASSOCIATE request - IPv4 hint is 10 bytes
            din.readFully(ByteArray(10))
            // reply with IPv6 BND
            val reply = byteArrayOf(
                0x05.toByte(),
                SocksReplyCode.SUCCEEDED.code,
                0x00.toByte(),
                0x04.toByte(), // IPv6 ATYP
            ) + ipv6Addr.address + byteArrayOf(
                (bndPort ushr 8 and 0xFF).toByte(),
                (bndPort and 0xFF).toByte(),
            )
            dout.write(reply); dout.flush()
        }

        runBlocking {
            val sock = client(port).udpAssociate(loopback)
            assertEquals(bndPort, sock.relayEndpointForTest.port)
            sock.close()
        }
    }

    // -------------------------------------------------------------------------
    // Test 8: DOMAIN BND ADDR 0x03 throws ProtocolViolation
    // -------------------------------------------------------------------------

    @Test
    fun `DOMAIN BND ADDR ATYP 0x03 throws ProtocolViolation`() {
        val port = runMockProxy { din, dout ->
            din.readByte(); val n = din.readUnsignedByte(); din.readFully(ByteArray(n))
            dout.write(byteArrayOf(0x05.toByte(), 0x00.toByte())); dout.flush()
            din.readFully(ByteArray(10))
            val domain = "example.com".toByteArray(Charsets.US_ASCII)
            val reply = byteArrayOf(
                0x05.toByte(),
                SocksReplyCode.SUCCEEDED.code,
                0x00.toByte(),
                0x03.toByte(),   // DOMAIN ATYP
                domain.size.toByte(),
            ) + domain + byteArrayOf(0x01.toByte(), 0xBB.toByte()) // port 443
            dout.write(reply); dout.flush()
        }

        val ex = assertFailsWith<SocksClientException.ProtocolViolation> {
            runBlocking { client(port).udpAssociate(loopback) }
        }
        assertTrue(ex.message!!.contains("DOMAIN"), "message should mention DOMAIN")
    }

    // -------------------------------------------------------------------------
    // Test 9: BND ADDR 0.0.0.0 substituted with TCP peer address (A-F6)
    // -------------------------------------------------------------------------

    @Test
    fun `BND ADDR 0_0_0_0 is substituted with TCP peer address`() {
        val port = runMockProxy { din, dout ->
            din.readByte(); val n = din.readUnsignedByte(); din.readFully(ByteArray(n))
            dout.write(byteArrayOf(0x05.toByte(), 0x00.toByte())); dout.flush()
            din.readFully(ByteArray(10))
            // BND.ADDR = 0.0.0.0, BND.PORT = 5555
            val reply = byteArrayOf(
                0x05.toByte(),
                SocksReplyCode.SUCCEEDED.code,
                0x00.toByte(),
                0x01.toByte(),
                0, 0, 0, 0,    // 0.0.0.0
                (5555 ushr 8 and 0xFF).toByte(),
                (5555 and 0xFF).toByte(),
            )
            dout.write(reply); dout.flush()
        }

        runBlocking {
            val sock = client(port).udpAssociate(loopback)
            // 0.0.0.0 must be replaced by the TCP peer address (loopback)
            val relayAddr = sock.relayEndpointForTest.address
            assertTrue(relayAddr.isLoopbackAddress, "relay address should be loopback, was $relayAddr")
            sock.close()
        }
    }
}
