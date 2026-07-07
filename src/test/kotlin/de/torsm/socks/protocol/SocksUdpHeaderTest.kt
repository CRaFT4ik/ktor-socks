package de.torsm.socks.protocol

import org.junit.jupiter.api.Test
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SocksUdpHeaderTest {

    @Test
    fun `wrapIpv4 emits RSV(2)+FRAG+ATYP=1+addr(4)+port(2)+payload`() {
        val payload = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val dst = InetSocketAddress(Inet4Address.getByName("192.0.2.1") as Inet4Address, 4321)
        val out = SocksUdpHeader.wrap(dst, payload)
        val expected = byteArrayOf(
            0x00.toByte(), 0x00.toByte(),
            0x00.toByte(),
            0x01.toByte(),
            192.toByte(), 0x00.toByte(), 0x02.toByte(), 0x01.toByte(),
            (4321 ushr 8).toByte(), (4321 and 0xFF).toByte(),
            0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte(),
        )
        assertContentEquals(expected, out)
        assertEquals(10, out.size - payload.size)
    }

    @Test
    fun `wrapIpv6 emits ATYP=4 with 22 byte header`() {
        val payload = byteArrayOf(1.toByte(), 2.toByte(), 3.toByte())
        val addr = Inet6Address.getByName("2001:db8::1") as Inet6Address
        val out = SocksUdpHeader.wrap(InetSocketAddress(addr, 80), payload)
        assertEquals(0x04.toByte(), out[3])
        assertEquals(22 + payload.size, out.size)
    }

    @Test
    fun `parse IPv4 returns dst and strips header`() {
        val payload = byteArrayOf(1.toByte(), 2.toByte(), 3.toByte())
        val dst = InetSocketAddress(Inet4Address.getByName("10.0.0.1") as Inet4Address, 9999)
        val wrapped = SocksUdpHeader.wrap(dst, payload)
        val parsed = SocksUdpHeader.parse(wrapped, wrapped.size)
        assertEquals(InetSocketAddress(dst.address, dst.port), parsed.destination)
        assertNull(parsed.hostName)
        assertContentEquals(payload, parsed.payload)
    }

    @Test
    fun `parse DOMAIN returns unresolved hostName and no destination`() {
        val payload = byteArrayOf(9.toByte(), 9.toByte(), 9.toByte())
        val wrapped = SocksUdpHeader.wrapDomain("example.com", 443, payload)
        val parsed = SocksUdpHeader.parse(wrapped, wrapped.size)
        assertNull(parsed.destination)
        assertEquals("example.com", parsed.hostName)
        assertEquals(443, parsed.port)
        assertContentEquals(payload, parsed.payload)
    }

    @Test
    fun `parse FRAG != 0 throws FragmentationNotSupported`() {
        val bad = byteArrayOf(
            0x00.toByte(), 0x00.toByte(), 0x01.toByte(),
            0x01.toByte(),
            192.toByte(), 0.toByte(), 2.toByte(), 1.toByte(),
            0x00.toByte(), 0x50.toByte(),
        )
        assertFailsWith<SocksProtocolException.FragmentationNotSupported> {
            SocksUdpHeader.parse(bad, bad.size)
        }
    }

    @Test
    fun `parse unknown ATYP throws UnsupportedAtype`() {
        val bad = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x99.toByte(),
                              1.toByte(), 2.toByte(), 3.toByte(), 4.toByte(),
                              0x00.toByte(), 0x00.toByte())
        assertFailsWith<SocksProtocolException.UnsupportedAtype> {
            SocksUdpHeader.parse(bad, bad.size)
        }
    }

    @Test
    fun `parse short buffer throws MalformedHeader`() {
        assertFailsWith<SocksProtocolException.MalformedHeader> {
            SocksUdpHeader.parse(byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x00.toByte()), 3)
        }
    }

    @Test
    fun `parse rsv nonzero is accepted per RFC not-required check`() {
        val ok = byteArrayOf(
            0x01.toByte(), 0x02.toByte(),
            0x00.toByte(),
            0x01.toByte(),
            10.toByte(), 0.toByte(), 0.toByte(), 1.toByte(),
            0x00.toByte(), 0x50.toByte(),
            0x77.toByte(),
        )
        val parsed = SocksUdpHeader.parse(ok, ok.size)
        assertTrue(parsed.destination != null)
    }
}
