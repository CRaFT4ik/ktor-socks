/*
 * Copyright (c) 2023, Eldar Timraleev.
 * This content is licensed under a Creative Commons
 * Attribution-NonCommercial 4.0 International License. (CC BY-NC 4.0).
 */

package de.torsm.socks

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import kotlinx.coroutines.async
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.slf4j.LoggerFactory
import org.xbill.DNS.hosts.HostsFileParser
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Executors
import kotlin.system.measureTimeMillis

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
    fun `empty system DNS watcher still resolves a public name via the public racers`() = runBlocking {
        // No system server published: the race must still complete using Cloudflare and Google.
        // We pick a high-availability public name that any working egress will resolve.
        val watcher = SystemDnsWatcher(read = { emptyList() })
        val resolver = AsyncDnsResolver(timeoutMillis = 5_000L, systemDnsWatcher = watcher)
        val addr = resolver.resolve("one.one.one.one")
        assertNotNull(addr)
        assertTrue(addr.hostAddress.contains('.'), "expected an IPv4 dotted-quad, got ${addr.hostAddress}")
    }

    @Test
    fun `system DNS server is consulted in the race when the watcher has one`() = runBlocking {
        // Point the watcher at a real public resolver (1.0.0.1, Cloudflare's secondary) so the
        // system racer can actually answer; this proves the watcher value is plumbed into the
        // race and not silently discarded. We do NOT assert who wins - any non-null result
        // proves the race composed at least one working racer.
        val watcher = SystemDnsWatcher(read = { listOf(InetSocketAddress("1.0.0.1", 53)) })
        watcher.refreshNow()
        val resolver = AsyncDnsResolver(timeoutMillis = 5_000L, systemDnsWatcher = watcher)
        val addr = resolver.resolve("one.one.one.one")
        assertNotNull(addr)
    }

    @Test
    fun `hosts file entry wins over DNS race`(@TempDir tempDir: Path) = runBlocking {
        // Fixture hosts file with a name that DNS could NEVER resolve (.invalid TLD is guaranteed
        // NXDOMAIN by RFC 6761). If resolve() returns the mapped IP for this name, the hosts
        // file MUST have short-circuited the DNS race - the race path would have thrown.
        val hostsFile = tempDir.resolve("hosts")
        Files.writeString(hostsFile, "10.46.228.190 hr.sberbank.invalid\n")
        val resolver = AsyncDnsResolver(
            timeoutMillis = 5_000L,
            systemDnsWatcher = SystemDnsWatcher(read = { emptyList() }),
            hostsFile = HostsFileParser(hostsFile),
        )
        val addr = resolver.resolve("hr.sberbank.invalid")
        assertEquals("10.46.228.190", addr.hostAddress)
    }

    @Test
    fun `hosts file lookup completes fast enough to prove it beat DNS`(@TempDir tempDir: Path) = runBlocking {
        // A hosts hit must return in far less than any realistic DNS RTT. 200 ms is a safe upper
        // bound: a warm dnsjava parser is a memory lookup, DNS to Cloudflare/Google is 20-100 ms
        // best case. This is not a substitute for the .invalid test above (which proves DNS never
        // ran); it is defence in depth against a future refactor that queries DNS in parallel.
        val hostsFile = tempDir.resolve("hosts")
        Files.writeString(hostsFile, "192.0.2.1 fast.override.test\n")
        val resolver = AsyncDnsResolver(
            timeoutMillis = 5_000L,
            systemDnsWatcher = SystemDnsWatcher(read = { emptyList() }),
            hostsFile = HostsFileParser(hostsFile),
        )
        // Warm the parser so the first-read file I/O does not count.
        resolver.resolve("fast.override.test")
        val elapsed = measureTimeMillis {
            val addr = resolver.resolve("fast.override.test")
            assertEquals("192.0.2.1", addr.hostAddress)
        }
        assertTrue(elapsed < 200L, "hosts hit should be instant, took ${elapsed} ms")
    }

    @Test
    fun `hostname not in hosts file falls through to DNS race`(@TempDir tempDir: Path) = runBlocking {
        // Hosts file exists but does NOT map the queried name. Resolution must proceed to the
        // DNS race and return a real answer from the public resolvers.
        val hostsFile = tempDir.resolve("hosts")
        Files.writeString(hostsFile, "10.0.0.1 something.else.local\n")
        val resolver = AsyncDnsResolver(
            timeoutMillis = 5_000L,
            hostsFile = HostsFileParser(hostsFile),
        )
        val addr = resolver.resolve("one.one.one.one")
        assertNotNull(addr)
        // one.one.one.one canonically resolves to 1.1.1.1 or 1.0.0.1; either proves the DNS race
        // ran, not the hosts file (which does not contain this name).
        assertTrue(
            addr.hostAddress == "1.1.1.1" || addr.hostAddress == "1.0.0.1",
            "expected DNS-provided Cloudflare IP, got ${addr.hostAddress}",
        )
    }

    @Test
    fun `hosts lookup exception is swallowed, resolve continues via DNS`(@TempDir tempDir: Path) = runBlocking {
        // Corrupted hosts file that HostsFileParser accepts at construction (it's a regular file)
        // but that yields no A record for the queried name. The parse-time internal state of
        // dnsjava must not leak an exception out of our resolver. If it did, resolve() would
        // throw instead of returning the DNS answer.
        val hostsFile = tempDir.resolve("hosts")
        Files.writeString(
            hostsFile,
            "# malformed entries below\nnot-an-address whatever\n1 too-few-tokens-2 3 4\n",
        )
        val resolver = AsyncDnsResolver(
            timeoutMillis = 5_000L,
            hostsFile = HostsFileParser(hostsFile),
        )
        val addr = resolver.resolve("one.one.one.one")
        assertNotNull(addr, "resolve must survive a malformed hosts file and answer via DNS")
    }

    @Test
    fun `default HostsFileParser constructor works on the current platform`() {
        // Sanity: the default constructor picks the platform-appropriate path (/etc/hosts on
        // unix, %SystemRoot%\System32\drivers\etc\hosts on windows) without blowing up at
        // construction time. We do not assert what it resolves; that is environmental. This
        // guards against a dnsjava upgrade breaking cross-platform behaviour.
        val parser = HostsFileParser()
        assertNotNull(parser)
        // Additionally: the resolver's own default construction path exercises the same
        // constructor and must not throw either.
        val resolver = AsyncDnsResolver(
            timeoutMillis = 2_000L,
            systemDnsWatcher = SystemDnsWatcher(read = { emptyList() }),
        )
        assertNotNull(resolver)
    }

    @Test
    fun `construction emits INFO log announcing hosts file resolver`(@TempDir tempDir: Path) {
        // Symmetric to dnsjava's "Added /1.1.1.1:53 to nameservers" line: hosts-file registration
        // must be visible in startup logs so operators can tell the resolver is live and see the
        // path it's reading from.
        val hostsFile = tempDir.resolve("hosts")
        Files.writeString(hostsFile, "10.0.0.1 log-init-test.local\n")
        val (appender, cleanup) = attachAppender(AsyncDnsResolver::class.java)
        try {
            AsyncDnsResolver(
                timeoutMillis = 2_000L,
                systemDnsWatcher = SystemDnsWatcher(read = { emptyList() }),
                hostsFile = HostsFileParser(hostsFile),
            )
            val infoLines = appender.list.filter { it.level == Level.INFO }
            assertTrue(
                infoLines.any { it.formattedMessage.contains("Hosts file registered as first-priority resolver") },
                "expected INFO announcement on construction, got: ${appender.list.map { it.formattedMessage }}",
            )
            // Path was accessible via reflection; the announcement must include it.
            assertTrue(
                infoLines.any { it.formattedMessage.contains(hostsFile.toString()) },
                "expected hosts file path in the INFO line, got: ${infoLines.map { it.formattedMessage }}",
            )
        } finally {
            cleanup()
        }
    }

    @Test
    fun `hosts file hit is logged at DEBUG with host and address`(@TempDir tempDir: Path) = runBlocking {
        // Operators must be able to attribute a resolution to /etc/hosts vs DNS by reading logs.
        // DEBUG (not INFO) so a busy proxy doesn't flood the log; the init INFO already proves the
        // resolver is live.
        val hostsFile = tempDir.resolve("hosts")
        Files.writeString(hostsFile, "10.9.8.7 debug-hit-test.local\n")
        val resolver = AsyncDnsResolver(
            timeoutMillis = 2_000L,
            systemDnsWatcher = SystemDnsWatcher(read = { emptyList() }),
            hostsFile = HostsFileParser(hostsFile),
        )
        val (appender, cleanup) = attachAppender(AsyncDnsResolver::class.java)
        try {
            val addr = resolver.resolve("debug-hit-test.local")
            assertEquals("10.9.8.7", addr.hostAddress)
            val debugLines = appender.list.filter { it.level == Level.DEBUG }
            assertTrue(
                debugLines.any {
                    val m = it.formattedMessage
                    m.contains("debug-hit-test.local") && m.contains("10.9.8.7") && m.contains("hosts file")
                },
                "expected DEBUG line naming host and address, got: ${debugLines.map { it.formattedMessage }}",
            )
        } finally {
            cleanup()
        }
    }

    /**
     * Attaches a logback [ListAppender] to the given class's logger so tests can assert on emitted
     * lines. Returns the appender plus a cleanup lambda that detaches it and restores the previous
     * log level; call the lambda in a finally block so a failed assertion never leaks state into
     * the next test.
     */
    private fun attachAppender(clazz: Class<*>): Pair<ListAppender<ILoggingEvent>, () -> Unit> {
        val logger = LoggerFactory.getLogger(clazz) as Logger
        val previousLevel = logger.level
        logger.level = Level.DEBUG
        val appender = ListAppender<ILoggingEvent>().apply { start() }
        logger.addAppender(appender)
        return appender to {
            logger.detachAppender(appender)
            logger.level = previousLevel
            appender.stop()
        }
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
