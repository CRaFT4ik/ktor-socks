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
}
