package de.torsm.socks.protocol

import org.junit.jupiter.api.Test
import java.net.Inet4Address
import java.net.Inet6Address
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AddressCodecTest {

    @Test
    fun `writeIpv4 emits ATYP=1 + 4 addr + 2 port`() {
        val buf = AddressCodec.writeToByteArray(Inet4Address.getByName("192.0.2.1"), 4321)
        val expected = byteArrayOf(
            0x01.toByte(),
            192.toByte(), 0.toByte(), 2.toByte(), 1.toByte(),
            (4321 ushr 8).toByte(), (4321 and 0xFF).toByte(),
        )
        assertContentEquals(expected, buf)
    }

    @Test
    fun `writeIpv6 emits ATYP=4 + 16 addr + 2 port`() {
        val addr = Inet6Address.getByName("2001:db8::1") as Inet6Address
        val buf = AddressCodec.writeToByteArray(addr, 80)
        assertEquals(0x04.toByte(), buf[0])
        assertEquals(1 + 16 + 2, buf.size)
    }

    @Test
    fun `readFromByteArray IPv4 round trip`() {
        val raw = byteArrayOf(0x01.toByte(), 10.toByte(), 0.toByte(), 0.toByte(), 1.toByte(),
                              0.toByte(), 80.toByte())
        val (addr, port, consumed) = AddressCodec.readIpFromByteArray(raw, 0, raw.size)
        assertEquals("10.0.0.1", addr.hostAddress)
        assertEquals(80, port)
        assertEquals(7, consumed)
    }

    @Test
    fun `readGeneric DOMAIN returns unresolved host`() {
        val name = "example.com".toByteArray(Charsets.US_ASCII)
        val raw = ByteArray(1 + 1 + name.size + 2)
        raw[0] = 0x03.toByte()
        raw[1] = name.size.toByte()
        name.copyInto(raw, 2)
        raw[raw.size - 2] = 0x01.toByte()
        raw[raw.size - 1] = 0xBB.toByte()
        val p = AddressCodec.readGeneric(raw, 0, raw.size)
        assertEquals("example.com", p.host)
        assertEquals(0x01BB, p.port)
    }

    @Test
    fun `readFromByteArray unknown ATYP throws UnsupportedAtype`() {
        val raw = byteArrayOf(0x99.toByte(), 0.toByte(), 0.toByte(), 0.toByte(), 0.toByte())
        assertFailsWith<SocksProtocolException.UnsupportedAtype> {
            AddressCodec.readGeneric(raw, 0, raw.size)
        }
    }

    @Test
    fun `readFromByteArray truncated buffer throws MalformedHeader`() {
        val raw = byteArrayOf(0x01.toByte(), 1.toByte(), 2.toByte())
        assertFailsWith<SocksProtocolException.MalformedHeader> {
            AddressCodec.readGeneric(raw, 0, raw.size)
        }
    }
}
