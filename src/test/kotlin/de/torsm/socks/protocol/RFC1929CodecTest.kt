package de.torsm.socks.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RFC1929CodecTest {

    @Test
    fun `encodeRequest emits VER ULEN UNAME PLEN PASSWD`() {
        val out = RFC1929Codec.encodeRequest("alice", "s3cret")
        val expected = byteArrayOf(
            0x01.toByte(),
            0x05.toByte(),
            'a'.code.toByte(), 'l'.code.toByte(), 'i'.code.toByte(), 'c'.code.toByte(), 'e'.code.toByte(),
            0x06.toByte(),
            's'.code.toByte(), '3'.code.toByte(), 'c'.code.toByte(), 'r'.code.toByte(), 'e'.code.toByte(), 't'.code.toByte(),
        )
        assertContentEquals(expected, out)
    }

    @Test
    fun `encodeRequest length 1 and 255 accepted`() {
        assertEquals(1 + 1 + 1 + 1 + 1, RFC1929Codec.encodeRequest("a", "b").size)
        val u = "u".repeat(255)
        val p = "p".repeat(255)
        assertEquals(1 + 1 + 255 + 1 + 255, RFC1929Codec.encodeRequest(u, p).size)
    }

    @Test
    fun `encodeRequest rejects empty username`() {
        assertFailsWith<IllegalArgumentException> { RFC1929Codec.encodeRequest("", "p") }
    }

    @Test
    fun `encodeRequest rejects empty password`() {
        assertFailsWith<IllegalArgumentException> { RFC1929Codec.encodeRequest("u", "") }
    }

    @Test
    fun `encodeRequest rejects username len 256`() {
        assertFailsWith<IllegalArgumentException> { RFC1929Codec.encodeRequest("a".repeat(256), "p") }
    }

    @Test
    fun `encodeRequest rejects password len 256`() {
        assertFailsWith<IllegalArgumentException> { RFC1929Codec.encodeRequest("u", "p".repeat(256)) }
    }

    @Test
    fun `decodeRequest round trip on len 1 254 255`() {
        for (n in intArrayOf(1, 2, 254, 255)) {
            val u = "u".repeat(n)
            val p = "p".repeat(n)
            val bytes = RFC1929Codec.encodeRequest(u, p)
            val d = RFC1929Codec.decodeRequest(bytes)
            assertEquals(u, d.username)
            assertEquals(p, d.password)
        }
    }

    @Test
    fun `decodeRequest ULEN=0 throws MalformedHeader`() {
        val bad = byteArrayOf(0x01.toByte(), 0x00.toByte(), 0x01.toByte(), 'p'.code.toByte())
        assertFailsWith<SocksProtocolException.MalformedHeader> { RFC1929Codec.decodeRequest(bad) }
    }

    @Test
    fun `decodeRequest PLEN=0 throws MalformedHeader`() {
        val bad = byteArrayOf(0x01.toByte(), 0x01.toByte(), 'u'.code.toByte(), 0x00.toByte())
        assertFailsWith<SocksProtocolException.MalformedHeader> { RFC1929Codec.decodeRequest(bad) }
    }

    @Test
    fun `parseResponse success STATUS 0x00`() {
        assertTrue(RFC1929Codec.parseResponse(byteArrayOf(0x01.toByte(), 0x00.toByte())))
    }

    @Test
    fun `parseResponse failure STATUS 0x01`() {
        assertFalse(RFC1929Codec.parseResponse(byteArrayOf(0x01.toByte(), 0x01.toByte())))
    }

    @Test
    fun `parseResponse rejects VER != 1`() {
        assertFailsWith<SocksProtocolException.MalformedHeader> {
            RFC1929Codec.parseResponse(byteArrayOf(0x05.toByte(), 0x00.toByte()))
        }
    }

    @Test
    fun `parseResponse rejects short buffer`() {
        assertFailsWith<SocksProtocolException.MalformedHeader> {
            RFC1929Codec.parseResponse(byteArrayOf(0x01.toByte()))
        }
    }
}
