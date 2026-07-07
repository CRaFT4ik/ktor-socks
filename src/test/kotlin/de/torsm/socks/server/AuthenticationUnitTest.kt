package de.torsm.socks.server

import io.ktor.utils.io.*
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertFailsWith

/**
 * Unit tests for [UsernamePasswordAuthentication.negotiate].
 *
 * Exercises RFC 1929 wire-level guards for zero-length username/password fields
 * (ULEN=0, PLEN=0), which must be rejected with a FAILURE response and a [SOCKSException].
 */
class AuthenticationUnitTest {

    /** Returns a [ByteReadChannel] pre-loaded with [bytes] (as unsigned int values). */
    private fun readerOf(vararg bytes: Int): ByteReadChannel =
        ByteReadChannel(ByteArray(bytes.size) { bytes[it].toByte() })

    /** Returns a write channel that discards all bytes written to it. */
    private fun discardWriter(): ByteWriteChannel = ByteChannel(autoFlush = true)

    private val auth = object : UsernamePasswordAuthentication() {
        override fun verify(username: String, password: String): Boolean = true
    }

    // -------------------------------------------------------------------------
    // ULEN=0 guard (FIX-3)
    // -------------------------------------------------------------------------

    @Test
    fun `ULEN=0 throws SOCKSException`() = runBlocking {
        // RFC 1929 wire: VER=1, ULEN=0
        val reader = readerOf(0x01, 0x00)
        val writer = discardWriter()
        assertFailsWith<SOCKSException> {
            auth.negotiate(reader, writer)
        }
    }

    // -------------------------------------------------------------------------
    // PLEN=0 guard (FIX-3)
    // -------------------------------------------------------------------------

    @Test
    fun `PLEN=0 throws SOCKSException`() = runBlocking {
        // RFC 1929 wire: VER=1, ULEN=1, UNAME="a", PLEN=0
        val reader = readerOf(0x01, 0x01, 'a'.code, 0x00)
        val writer = discardWriter()
        assertFailsWith<SOCKSException> {
            auth.negotiate(reader, writer)
        }
    }

    // -------------------------------------------------------------------------
    // Happy-path: valid credentials pass through
    // -------------------------------------------------------------------------

    @Test
    fun `valid username and password succeed`() = runBlocking {
        // RFC 1929 wire: VER=1, ULEN=4, UNAME="user", PLEN=4, PASSWD="pass"
        val reader = readerOf(
            0x01,
            0x04, 'u'.code, 's'.code, 'e'.code, 'r'.code,
            0x04, 'p'.code, 'a'.code, 's'.code, 's'.code,
        )
        val writer = discardWriter()
        // Should not throw; verify() returns true above.
        auth.negotiate(reader, writer)
    }
}
