package de.torsm.socks.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SocksReplyCodeTest {
    @Test
    fun `all nine RFC 1928 6 codes round-trip`() {
        val mapping = mapOf<Byte, SocksReplyCode>(
            0x00.toByte() to SocksReplyCode.SUCCEEDED,
            0x01.toByte() to SocksReplyCode.GENERAL_FAILURE,
            0x02.toByte() to SocksReplyCode.CONNECTION_NOT_ALLOWED,
            0x03.toByte() to SocksReplyCode.NETWORK_UNREACHABLE,
            0x04.toByte() to SocksReplyCode.HOST_UNREACHABLE,
            0x05.toByte() to SocksReplyCode.CONNECTION_REFUSED,
            0x06.toByte() to SocksReplyCode.TTL_EXPIRED,
            0x07.toByte() to SocksReplyCode.COMMAND_NOT_SUPPORTED,
            0x08.toByte() to SocksReplyCode.ADDRESS_TYPE_NOT_SUPPORTED,
        )
        for ((raw, code) in mapping) {
            assertEquals(code, SocksReplyCode.of(raw))
            assertEquals(raw, code.code)
        }
    }
    @Test
    fun `unknown code falls back to UNKNOWN raw`() {
        val u = SocksReplyCode.of(0x42.toByte())
        assertTrue(u is SocksReplyCode.Unknown)
        assertEquals(0x42.toByte(), (u as SocksReplyCode.Unknown).raw)
    }
    @Test
    fun `name of known code is stable`() {
        assertEquals("SUCCEEDED", SocksReplyCode.SUCCEEDED.name)
        assertEquals("HOST_UNREACHABLE", SocksReplyCode.HOST_UNREACHABLE.name)
    }
}
