package de.torsm.socks

import io.ktor.utils.io.streams.*
import org.junit.jupiter.api.extension.ExtendWith
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Low-level wire-format tests verifying RFC 1928 compliance.
 * Each test opens a raw TCP connection to the proxy and speaks SOCKS5 directly
 * so that exact reply codes can be asserted without relying on the Java SOCKS library.
 */
@ExtendWith(MockServers::class)
class RFC1928ComplianceTests {

    // -------------------------------------------------------------------------
    // Wire-level helpers
    // -------------------------------------------------------------------------

    /**
     * Open a raw TCP connection to the proxy server (bypassing the SOCKS library).
     * A 2-second SO_TIMEOUT prevents any read from blocking indefinitely.
     */
    private fun rawSocket(): Socket = Socket().also {
        it.soTimeout = 2_000
        it.connect(proxyServerJava)
    }

    /**
     * Send the SOCKS5 greeting (VER + NMETHODS + METHODS) and read back the
     * method-selection reply (VER + METHOD). Returns the selected METHOD byte (0–255).
     */
    private fun greet(out: OutputStream, inp: InputStream, vararg methods: Int): Int {
        val dos = DataOutputStream(out)
        dos.writeByte(0x05)                      // VER
        dos.writeByte(methods.size)              // NMETHODS
        methods.forEach { dos.writeByte(it) }
        dos.flush()

        assertEquals(0x05, inp.read(), "VER in method-selection reply")
        return inp.read()
    }

    /**
     * Read a full SOCKS5 reply and return just the REP byte (0–255).
     * Consumes RSV, ATYP, BND.ADDR, and BND.PORT so the stream is left clean.
     */
    private fun readFullReply(inp: InputStream): Int {
        assertEquals(0x05, inp.read(), "VER in reply")
        val rep = inp.read()
        assertEquals(0x00, inp.read(), "RSV in reply must be 0x00")
        val atyp = inp.read()
        when (atyp) {
            0x01 -> inp.readNBytes(4)
            0x04 -> inp.readNBytes(16)
            0x03 -> inp.readNBytes(inp.read())
        }
        inp.readNBytes(2)  // BND.PORT
        return rep
    }

    // -------------------------------------------------------------------------
    // Test: no acceptable methods → server MUST reply X'FF' and close
    // RFC 1928 §3: "If the selected METHOD is X'FF', none of the methods listed
    // by the client are acceptable, and the client MUST close the connection."
    // -------------------------------------------------------------------------

    @Test
    fun `no acceptable methods - server replies 0xFF then closes`() {
        rawSocket().use { s ->
            val inp = s.getInputStream()
            val out = s.getOutputStream()
            // Offer only method 0x01 (GSSAPI) which the server does not support
            val method = greet(out, inp, 0x01)
            assertEquals(0xFF, method and 0xFF,
                "Server must reply 0xFF when no common method exists (RFC 1928 §3)")
            // After 0xFF the server must close the connection; read returns -1 or throws on timeout
            val eof = inp.read()
            assertEquals(-1, eof, "Server must close connection after replying 0xFF")
        }
    }

    // -------------------------------------------------------------------------
    // Test: unknown CMD → server must reply REP=X'07' (command not supported)
    // RFC 1928 §6: reply code X'07' = "Command not supported"
    // -------------------------------------------------------------------------

    @Test
    fun `unknown command byte - server replies REP 0x07`() {
        rawSocket().use { s ->
            val inp = s.getInputStream()
            val out = s.getOutputStream()
            greet(out, inp, 0x00)   // NO AUTH

            val dos = DataOutputStream(out)
            dos.writeByte(0x05)   // VER
            dos.writeByte(0x42)   // CMD = 0x42, undefined
            dos.writeByte(0x00)   // RSV
            dos.writeByte(0x01)   // ATYP = IPv4
            dos.writeByte(127); dos.writeByte(0); dos.writeByte(0); dos.writeByte(1)
            dos.writeShort(8080)
            dos.flush()

            val rep = readFullReply(inp)
            assertEquals(0x07, rep,
                "Unknown CMD must produce REP=X'07' (command not supported, RFC 1928 §6)")
        }
    }

    // -------------------------------------------------------------------------
    // Test: unknown ATYP → server must reply REP=X'08' (address type not supported)
    // RFC 1928 §6: reply code X'08' = "Address type not supported"
    // -------------------------------------------------------------------------

    @Test
    fun `unknown address type - server replies REP 0x08`() {
        rawSocket().use { s ->
            val inp = s.getInputStream()
            val out = s.getOutputStream()
            greet(out, inp, 0x00)   // NO AUTH

            val dos = DataOutputStream(out)
            dos.writeByte(0x05)   // VER
            dos.writeByte(0x01)   // CMD = CONNECT
            dos.writeByte(0x00)   // RSV
            dos.writeByte(0x02)   // ATYP = 0x02, undefined in RFC 1928
            // Stop here – server should reject with 0x08 without needing DST.ADDR
            dos.flush()

            assertEquals(0x05, inp.read(), "VER in reply")
            val rep = inp.read()
            assertEquals(0x08, rep,
                "Unknown ATYP must produce REP=X'08' (address type not supported, RFC 1928 §6)")
        }
    }

    // -------------------------------------------------------------------------
    // Test: CONNECT to a refused port → REP=X'05' (connection refused), not X'04'
    // RFC 1928 §6: reply code X'05' = "Connection refused"
    // -------------------------------------------------------------------------

    @Test
    fun `connection refused - server replies REP 0x05`() {
        rawSocket().use { s ->
            val inp = s.getInputStream()
            val out = s.getOutputStream()
            greet(out, inp, 0x00)   // NO AUTH

            val dos = DataOutputStream(out)
            dos.writeByte(0x05)   // VER
            dos.writeByte(0x01)   // CMD = CONNECT
            dos.writeByte(0x00)   // RSV
            dos.writeByte(0x01)   // ATYP = IPv4
            // 127.0.0.1:1 – reserved port, always connection-refused
            dos.writeByte(127); dos.writeByte(0); dos.writeByte(0); dos.writeByte(1)
            dos.writeShort(1)
            dos.flush()

            val rep = readFullReply(inp)
            assertEquals(0x05, rep,
                "Connection refused must produce REP=X'05' (RFC 1928 §6), not X'04' (host unreachable)")
        }
    }
}
