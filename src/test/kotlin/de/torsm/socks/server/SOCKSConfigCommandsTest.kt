package de.torsm.socks.server

import de.torsm.socks.protocol.SOCKSCommand
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SOCKSConfigCommandsTest {

    @Test
    fun `default commands is CONNECT only`() {
        val cfg = SOCKSConfigBuilder().build()
        assertEquals(setOf(SOCKSCommand.CONNECT), cfg.commands)
    }

    @Test
    fun `empty commands rejected at setter`() {
        val b = SOCKSConfigBuilder()
        assertFailsWith<IllegalArgumentException> { b.commands = emptySet() }
    }

    @Test
    fun `builder passes commands into config`() {
        val cfg = SOCKSConfigBuilder().apply {
            commands = setOf(SOCKSCommand.CONNECT, SOCKSCommand.UDP_ASSOCIATE)
        }.build()
        assertEquals(setOf(SOCKSCommand.CONNECT, SOCKSCommand.UDP_ASSOCIATE), cfg.commands)
    }

    @Test
    fun `default udpIdleAssociationTimeoutSeconds is 300`() {
        val cfg = SOCKSConfigBuilder().build()
        assertEquals(300L, cfg.udpIdleAssociationTimeoutSeconds)
    }

    @Test
    fun `udpIdleAssociationTimeoutSeconds=0 with UDP_ASSOCIATE rejected at build`() {
        assertFailsWith<IllegalArgumentException> {
            SOCKSConfigBuilder().apply {
                commands = setOf(SOCKSCommand.UDP_ASSOCIATE)
                udpIdleAssociationTimeoutSeconds = 0
            }.build()
        }
    }

    @Test
    fun `udpIdleAssociationTimeoutSeconds=86401 with UDP_ASSOCIATE rejected at build`() {
        assertFailsWith<IllegalArgumentException> {
            SOCKSConfigBuilder().apply {
                commands = setOf(SOCKSCommand.UDP_ASSOCIATE)
                udpIdleAssociationTimeoutSeconds = 86401
            }.build()
        }
    }

    @Test
    fun `udpIdleAssociationTimeoutSeconds=1 with UDP_ASSOCIATE accepted at build`() {
        val cfg = SOCKSConfigBuilder().apply {
            commands = setOf(SOCKSCommand.UDP_ASSOCIATE)
            udpIdleAssociationTimeoutSeconds = 1
        }.build()
        assertEquals(1L, cfg.udpIdleAssociationTimeoutSeconds)
    }

    @Test
    fun `udpIdleAssociationTimeoutSeconds=86400 with UDP_ASSOCIATE accepted at build`() {
        val cfg = SOCKSConfigBuilder().apply {
            commands = setOf(SOCKSCommand.UDP_ASSOCIATE)
            udpIdleAssociationTimeoutSeconds = 86400
        }.build()
        assertEquals(86400L, cfg.udpIdleAssociationTimeoutSeconds)
    }

    @Test
    fun `udpIdleAssociationTimeoutSeconds=0 without UDP_ASSOCIATE accepted at build`() {
        // Without UDP_ASSOCIATE the timeout field is irrelevant; no validation is applied.
        val cfg = SOCKSConfigBuilder().apply {
            commands = setOf(SOCKSCommand.CONNECT)
            udpIdleAssociationTimeoutSeconds = 0
        }.build()
        assertEquals(0L, cfg.udpIdleAssociationTimeoutSeconds)
    }
}
