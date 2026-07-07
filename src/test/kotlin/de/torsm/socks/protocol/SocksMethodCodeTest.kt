package de.torsm.socks.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SocksMethodCodeTest {
    @Test
    fun `codes 0x00 0x01 0x02 0xFF map to singletons`() {
        assertEquals(SocksMethodCode.NoAuth, SocksMethodCode.of(0x00.toByte()))
        assertEquals(SocksMethodCode.GssApi, SocksMethodCode.of(0x01.toByte()))
        assertEquals(SocksMethodCode.UserPass, SocksMethodCode.of(0x02.toByte()))
        assertEquals(SocksMethodCode.NoAcceptable, SocksMethodCode.of(0xFF.toByte()))
    }
    @Test
    fun `codes 0x03 through 0x7F map to IanaAssigned`() {
        val c = SocksMethodCode.of(0x40.toByte())
        assertTrue(c is SocksMethodCode.IanaAssigned)
        assertEquals(0x40.toByte(), c.code)
    }
    @Test
    fun `codes 0x80 through 0xFE map to Private`() {
        val c = SocksMethodCode.of(0x90.toByte())
        assertTrue(c is SocksMethodCode.Private)
        assertEquals(0x90.toByte(), c.code)
    }
}
