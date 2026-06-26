/*
 * Copyright (c) 2023, Eldar Timraleev.
 * This content is licensed under a Creative Commons
 * Attribution-NonCommercial 4.0 International License. (CC BY-NC 4.0).
 */

package de.torsm.socks

import kotlinx.coroutines.async
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.UnknownHostException
import java.util.concurrent.Executors

/**
 * Coverage for [AsyncDnsResolver].
 *
 * The thread-not-blocked test is the hard requirement: while one coroutine is mid-resolve, a
 * second coroutine scheduled on the same single-threaded dispatcher must still make progress.
 * If the resolver pinned the thread on socket I/O, the second coroutine would not run until the
 * resolve finished.
 */
internal class AsyncDnsResolverTest {

    @Test
    fun `unknown host throws UnknownHostException`() {
        val resolver = AsyncDnsResolver(timeoutMillis = 2_000L)
        assertThrows(UnknownHostException::class.java) {
            runBlocking { resolver.resolve("unreachable-test-host-12345.invalid") }
        }
    }

    @Test
    fun `ip literal short circuits without DNS`() = runBlocking {
        val resolver = AsyncDnsResolver(timeoutMillis = 2_000L)
        val addr = resolver.resolve("1.2.3.4")
        assertNotNull(addr)
        assertEquals("1.2.3.4", addr.hostAddress)
    }

    @Test
    fun `caller dispatcher thread is not blocked during resolve`() {
        val single = Executors.newSingleThreadExecutor { r ->
            Thread(r, "async-dns-test-single").apply { isDaemon = true }
        }
        val dispatcher = single.asCoroutineDispatcher()
        try {
            runBlocking {
                val resolver = AsyncDnsResolver(timeoutMillis = 3_000L)
                // Start a resolve that will take a while (NXDOMAIN goes through the full race
                // + fallback path; takes seconds end-to-end).
                val resolveJob = async(dispatcher) {
                    runCatching { resolver.resolve("unreachable-test-host-12345.invalid") }
                }
                // While the resolve is in flight, the same dispatcher must still run other work.
                // If resolve blocked the single thread, this small task would not complete in
                // sub-second time and the withTimeout would fire.
                val progress = async(dispatcher) {
                    System.currentTimeMillis()
                }
                val ts = withTimeout(500L) { progress.await() }
                assertTrue(ts > 0L, "co-running coroutine could not make progress")
                resolveJob.await()
            }
        } finally {
            dispatcher.close()
            single.shutdownNow()
        }
    }
}
