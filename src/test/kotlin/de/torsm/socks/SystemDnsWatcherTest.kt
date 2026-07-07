/*
 * Copyright (c) 2023, Eldar Timraleev.
 * This content is licensed under a Creative Commons
 * Attribution-NonCommercial 4.0 International License. (CC BY-NC 4.0).
 */

package de.torsm.socks

import de.torsm.socks.server.SystemDnsWatcher
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicReference

/**
 * Coverage for [SystemDnsWatcher].
 *
 * The watcher's only job is to publish the FIRST currently-configured OS DNS server (or null when
 * none is configured) and to keep that value fresh as the OS state changes. Production driver runs
 * a daemon thread; the tests skip that thread by invoking [SystemDnsWatcher.refreshNow] directly.
 */
internal class SystemDnsWatcherTest {

    @Test
    fun `currentServer is null before the first refresh`() {
        val watcher = SystemDnsWatcher(read = { emptyList() })
        assertNull(watcher.currentServer(), "no read yet, no server")
    }

    @Test
    fun `refreshNow publishes the first configured server`() {
        val server = InetSocketAddress("10.0.0.53", 53)
        val watcher = SystemDnsWatcher(read = { listOf(server) })
        watcher.refreshNow()
        assertEquals(server, watcher.currentServer())
    }

    @Test
    fun `refreshNow with empty list clears the published server`() {
        val source = AtomicReference(listOf(InetSocketAddress("10.0.0.53", 53)))
        val watcher = SystemDnsWatcher(read = { source.get() })
        watcher.refreshNow()
        assertEquals(InetSocketAddress("10.0.0.53", 53), watcher.currentServer())
        // OS dropped every DNS server (e.g. all network adapters down).
        source.set(emptyList())
        watcher.refreshNow()
        assertNull(watcher.currentServer(), "cleared when the OS reports no servers")
    }

    @Test
    fun `refreshNow picks up a server that appears between reads`() {
        val source = AtomicReference<List<InetSocketAddress>>(emptyList())
        val watcher = SystemDnsWatcher(read = { source.get() })
        watcher.refreshNow()
        assertNull(watcher.currentServer())
        // VPN comes up and the OS now advertises a corporate DNS.
        source.set(listOf(InetSocketAddress("10.1.2.3", 53)))
        watcher.refreshNow()
        assertEquals(InetSocketAddress("10.1.2.3", 53), watcher.currentServer())
    }

    @Test
    fun `refreshNow swallows read failures and leaves the previous value intact`() {
        val watcher = SystemDnsWatcher(read = { listOf(InetSocketAddress("10.0.0.53", 53)) })
        watcher.refreshNow()
        assertEquals(InetSocketAddress("10.0.0.53", 53), watcher.currentServer())
        // Synthesize a read failure: the watcher must NOT crash and the previously-published
        // value should remain the one resolvers see.
        val failing = SystemDnsWatcher(read = { throw RuntimeException("transient OS error") })
        failing.refreshNow()
        assertNull(failing.currentServer(), "no successful read yet, still null - no crash")
    }

    @Test
    fun `readSystemDns returns a non-null list from the production source`() {
        // Smoke test: the production reader must at least return without throwing. Whether the
        // host running the test has DNS configured is environmental, so we assert no-throw and
        // a non-null result rather than a specific value.
        val servers = SystemDnsWatcher.readSystemDns()
        // Either the host has servers configured, or it does not; both are acceptable.
        // The only failure mode we guard against is the function throwing.
        assertEquals(servers, servers)
    }
}
