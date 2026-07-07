package de.torsm.socks.client

import de.torsm.socks.protocol.SocksReplyCode
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SocksClientExceptionTest {

    // --- forReply mapping ---

    @Test
    fun `forReply GENERAL_FAILURE returns RelayReplyGeneralFailure`() {
        val ex = SocksClientException.forReply(SocksReplyCode.GENERAL_FAILURE)
        assertIs<SocksClientException.RelayReplyGeneralFailure>(ex)
    }

    @Test
    fun `forReply CONNECTION_NOT_ALLOWED returns RelayReplyConnectionNotAllowed`() {
        val ex = SocksClientException.forReply(SocksReplyCode.CONNECTION_NOT_ALLOWED)
        assertIs<SocksClientException.RelayReplyConnectionNotAllowed>(ex)
    }

    @Test
    fun `forReply NETWORK_UNREACHABLE returns RelayReplyNetworkUnreachable`() {
        val ex = SocksClientException.forReply(SocksReplyCode.NETWORK_UNREACHABLE)
        assertIs<SocksClientException.RelayReplyNetworkUnreachable>(ex)
    }

    @Test
    fun `forReply HOST_UNREACHABLE returns RelayReplyHostUnreachable`() {
        val ex = SocksClientException.forReply(SocksReplyCode.HOST_UNREACHABLE)
        assertIs<SocksClientException.RelayReplyHostUnreachable>(ex)
    }

    @Test
    fun `forReply CONNECTION_REFUSED returns RelayReplyConnectionRefused`() {
        val ex = SocksClientException.forReply(SocksReplyCode.CONNECTION_REFUSED)
        assertIs<SocksClientException.RelayReplyConnectionRefused>(ex)
    }

    @Test
    fun `forReply TTL_EXPIRED returns RelayReplyTtlExpired`() {
        val ex = SocksClientException.forReply(SocksReplyCode.TTL_EXPIRED)
        assertIs<SocksClientException.RelayReplyTtlExpired>(ex)
    }

    @Test
    fun `forReply COMMAND_NOT_SUPPORTED returns RelayReplyCommandNotSupported`() {
        val ex = SocksClientException.forReply(SocksReplyCode.COMMAND_NOT_SUPPORTED)
        assertIs<SocksClientException.RelayReplyCommandNotSupported>(ex)
    }

    @Test
    fun `forReply ADDRESS_TYPE_NOT_SUPPORTED returns RelayReplyAddressTypeNotSupported`() {
        val ex = SocksClientException.forReply(SocksReplyCode.ADDRESS_TYPE_NOT_SUPPORTED)
        assertIs<SocksClientException.RelayReplyAddressTypeNotSupported>(ex)
    }

    @Test
    fun `forReply Unknown returns RelayReplyUnknown`() {
        val ex = SocksClientException.forReply(SocksReplyCode.Unknown(0x42.toByte()))
        assertIs<SocksClientException.RelayReplyUnknown>(ex)
        assertTrue(ex.message!!.contains("0x42"), "message should include hex code")
    }

    @Test
    fun `forReply SUCCEEDED throws IllegalStateException`() {
        assertFailsWith<IllegalStateException> {
            SocksClientException.forReply(SocksReplyCode.SUCCEEDED)
        }
    }

    // --- retryable classification ---

    @Test
    fun `retryable codes are true`() {
        val retryable = listOf(
            SocksClientException.forReply(SocksReplyCode.GENERAL_FAILURE),
            SocksClientException.forReply(SocksReplyCode.NETWORK_UNREACHABLE),
            SocksClientException.forReply(SocksReplyCode.HOST_UNREACHABLE),
            SocksClientException.forReply(SocksReplyCode.CONNECTION_REFUSED),
            SocksClientException.forReply(SocksReplyCode.TTL_EXPIRED),
            SocksClientException.ProxyUnreachable(RuntimeException("tcp")),
            SocksClientException.ProxyTcpClosed(RuntimeException("io")),
        )
        for (ex in retryable) {
            assertTrue(ex.retryable, "expected retryable=true for ${ex.javaClass.simpleName}")
        }
    }

    @Test
    fun `fatal codes are not retryable`() {
        val fatal = listOf(
            SocksClientException.forReply(SocksReplyCode.CONNECTION_NOT_ALLOWED),
            SocksClientException.forReply(SocksReplyCode.COMMAND_NOT_SUPPORTED),
            SocksClientException.forReply(SocksReplyCode.ADDRESS_TYPE_NOT_SUPPORTED),
            SocksClientException.forReply(SocksReplyCode.Unknown(0x09.toByte())),
            SocksClientException.NotSocks5Proxy(0x04.toByte()),
            SocksClientException.NoSharedMethod(),
            SocksClientException.AuthFailed(),
            SocksClientException.ProtocolViolation("bad field"),
        )
        for (ex in fatal) {
            assertFalse(ex.retryable, "expected retryable=false for ${ex.javaClass.simpleName}")
        }
    }

    // --- SocksCredentials ---

    @Test
    fun `SocksCredentials toString redacts password`() {
        val creds = SocksCredentials("alice", "secret123")
        val str = creds.toString()
        assertTrue(str.contains("alice"), "username must appear in toString")
        assertFalse(str.contains("secret123"), "password must not appear in toString")
        assertTrue(str.contains("***"), "password placeholder must appear")
    }

    @Test
    fun `SocksCredentials empty username throws IllegalArgumentException`() {
        assertFailsWith<IllegalArgumentException> {
            SocksCredentials("", "pass")
        }
    }

    @Test
    fun `SocksCredentials empty password throws IllegalArgumentException`() {
        assertFailsWith<IllegalArgumentException> {
            SocksCredentials("user", "")
        }
    }

    @Test
    fun `SocksCredentials username too long throws IllegalArgumentException`() {
        val longUser = "a".repeat(256)
        assertFailsWith<IllegalArgumentException> {
            SocksCredentials(longUser, "pass")
        }
    }

    @Test
    fun `SocksCredentials password too long throws IllegalArgumentException`() {
        val longPass = "a".repeat(256)
        assertFailsWith<IllegalArgumentException> {
            SocksCredentials("user", longPass)
        }
    }

    @Test
    fun `SocksCredentials single char fields are valid`() {
        val creds = SocksCredentials("u", "p")
        assertEquals("u", creds.username)
        assertEquals("p", creds.password)
    }

    @Test
    fun `SocksCredentials equals and hashCode`() {
        val a = SocksCredentials("user", "pass")
        val b = SocksCredentials("user", "pass")
        val c = SocksCredentials("user", "other")
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertFalse(a == c)
    }

    // --- SocksClientConfig ---

    @Test
    fun `SocksClientConfig valid config constructs without error`() {
        val cfg = SocksClientConfig(proxyHost = "proxy.example.com", proxyPort = 1080)
        assertEquals("proxy.example.com", cfg.proxyHost)
        assertEquals(1080, cfg.proxyPort)
    }

    @Test
    fun `SocksClientConfig blank proxyHost throws`() {
        assertFailsWith<IllegalArgumentException> {
            SocksClientConfig(proxyHost = "  ", proxyPort = 1080)
        }
    }

    @Test
    fun `SocksClientConfig proxyPort 0 throws`() {
        assertFailsWith<IllegalArgumentException> {
            SocksClientConfig(proxyHost = "host", proxyPort = 0)
        }
    }

    @Test
    fun `SocksClientConfig proxyPort 65536 throws`() {
        assertFailsWith<IllegalArgumentException> {
            SocksClientConfig(proxyHost = "host", proxyPort = 65_536)
        }
    }

    @Test
    fun `SocksClientConfig proxyPort 1 and 65535 are valid`() {
        SocksClientConfig(proxyHost = "host", proxyPort = 1)
        SocksClientConfig(proxyHost = "host", proxyPort = 65_535)
    }

    @Test
    fun `SocksClientConfig connectTimeoutMillis below 100 throws`() {
        assertFailsWith<IllegalArgumentException> {
            SocksClientConfig(proxyHost = "host", proxyPort = 1080, connectTimeoutMillis = 99L)
        }
    }

    @Test
    fun `SocksClientConfig connectTimeoutMillis above 60000 throws`() {
        assertFailsWith<IllegalArgumentException> {
            SocksClientConfig(proxyHost = "host", proxyPort = 1080, connectTimeoutMillis = 60_001L)
        }
    }

    @Test
    fun `SocksClientConfig handshakeTimeoutMillis below 100 throws`() {
        assertFailsWith<IllegalArgumentException> {
            SocksClientConfig(proxyHost = "host", proxyPort = 1080, handshakeTimeoutMillis = 50L)
        }
    }

    @Test
    fun `SocksClientConfig handshakeTimeoutMillis above 60000 throws`() {
        assertFailsWith<IllegalArgumentException> {
            SocksClientConfig(proxyHost = "host", proxyPort = 1080, handshakeTimeoutMillis = 60_001L)
        }
    }
}
