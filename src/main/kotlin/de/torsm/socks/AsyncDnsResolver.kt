/*
 * Copyright (c) 2023, Eldar Timraleev.
 * This content is licensed under a Creative Commons
 * Attribution-NonCommercial 4.0 International License. (CC BY-NC 4.0).
 *
 * Async DNS extension for ktor-socks. The class lives in the same package as SOCKSHandshake
 * but is otherwise independent of the upstream ktor-socks code (no upstream files modified
 * besides the call site). LGPL fork: license headers in the upstream files remain intact.
 */

package de.torsm.socks

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.future.await
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.slf4j.LoggerFactory
import org.xbill.DNS.ARecord
import org.xbill.DNS.Lookup
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Resolver
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.Type
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicReference

/**
 * Non-blocking DNS resolver for hostnames received by the SOCKS5 handshake.
 *
 * Two upstream resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8) are queried in parallel;
 * whichever answers first wins. If neither answers within [timeoutMillis], the JDK system
 * resolver is consulted (off [Dispatchers.IO]) as a last-chance fallback so split-horizon
 * intranet names still resolve.
 *
 * Threading contract: [resolve] suspends but never blocks the caller's thread on socket I/O.
 * dnsjava's NIO event loop runs on its own daemon threads.
 *
 * On NXDOMAIN every path throws [UnknownHostException]. Other transient failures (timeout,
 * NoRouteToHost) also surface as [UnknownHostException] so the SOCKS5 server returns a sane
 * REP code to the client.
 *
 * @property timeoutMillis per-attempt timeout for each upstream resolver (race) and for the
 *   system fallback combined; total wall-clock is bounded by 2x [timeoutMillis] in the worst
 *   case (race timeout + system fallback timeout).
 */
public class AsyncDnsResolver(
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
) {

    private val log = LoggerFactory.getLogger(javaClass)

    private data class Resolvers(val cloudflare: SimpleResolver, val google: SimpleResolver)

    private val resolvers: AtomicReference<Resolvers?> = AtomicReference(null)

    private fun resolvers(): Resolvers? {
        resolvers.get()?.let { return it }
        return try {
            val cf = SimpleResolver("1.1.1.1").apply { timeout = java.time.Duration.ofMillis(timeoutMillis) }
            val go = SimpleResolver("8.8.8.8").apply { timeout = java.time.Duration.ofMillis(timeoutMillis) }
            val built = Resolvers(cf, go)
            resolvers.compareAndSet(null, built)
            resolvers.get()
        } catch (t: Throwable) {
            // Resolver construction itself failed (rare: bad address literal). Surface as null;
            // the resolve() path will fall back to the system resolver.
            log.warn("AsyncDnsResolver init failed, will fall back to system resolver: {}", t.toString())
            null
        }
    }

    /**
     * Resolves [host] to an [InetAddress] without blocking the caller's coroutine thread.
     *
     * Resolution order:
     *   1. Already an IPv4/IPv6 literal: [InetAddress.getByName] short-circuits, no DNS lookup.
     *   2. Race 1.1.1.1 / 8.8.8.8 over UDP via dnsjava NIO.
     *   3. If both upstreams time out or error, fall back to the system resolver on
     *      [Dispatchers.IO] (so a slow system resolver still does not pin the caller's thread).
     *
     * @throws UnknownHostException when no path produced an address.
     */
    public suspend fun resolve(host: String): InetAddress {
        // IP literals (a.b.c.d / IPv6) are not DNS names. Short-circuit via the JDK; this only
        // parses the literal, no resolver socket is touched.
        if (looksLikeIpLiteral(host)) {
            return try {
                InetAddress.getByName(host)
            } catch (e: UnknownHostException) {
                throw e
            }
        }

        val rs = resolvers()
        if (rs != null) {
            val raced = withTimeoutOrNull(timeoutMillis) {
                raceAsync(host, rs.cloudflare, rs.google)
            }
            if (raced != null) return raced
        }

        // Fallback path: the system resolver. Run on IO so a slow getaddrinfo doesn't pin the
        // caller thread; if it takes longer than timeoutMillis we give up.
        val fallback = withTimeoutOrNull(timeoutMillis) {
            withContext(Dispatchers.IO) {
                try {
                    InetAddress.getByName(host)
                } catch (e: UnknownHostException) {
                    null
                }
            }
        }
        return fallback ?: throw UnknownHostException(host)
    }

    private suspend fun raceAsync(host: String, a: Resolver, b: Resolver): InetAddress? {
        val name = try {
            Name.fromString(if (host.endsWith('.')) host else "$host.")
        } catch (_: Throwable) {
            return null
        }
        val query = Message.newQuery(org.xbill.DNS.Record.newRecord(name, Type.A, org.xbill.DNS.DClass.IN))

        // dnsjava sendAsync returns a CompletionStage<Message>; CompletableFuture.anyOf to race.
        val fa: CompletableFuture<Message> = a.sendAsync(query).toCompletableFuture()
        val fb: CompletableFuture<Message> = b.sendAsync(query).toCompletableFuture()
        try {
            val winner = try {
                // CompletableFuture.anyOf: first to complete (success OR failure) wins. Prefer a
                // SUCCESS path; if the winning future failed but the other one succeeded, fall
                // through to the loser.
                val any = CompletableFuture.anyOf(fa, fb).await()
                any as? Message
            } catch (_: Throwable) {
                null
            }

            val msg = winner ?: try {
                // If the first-to-complete failed, await the slower one as a salvage path.
                val slower = if (fa.isDone && fa.isCompletedExceptionally) fb else fa
                slower.await()
            } catch (_: Throwable) {
                return null
            }

            return pickFirstA(msg)
        } finally {
            // Cancel whichever future did not produce the returned answer so the dnsjava NIO
            // worker drops its pending UDP query state instead of waiting for the 5s timeout.
            // mayInterruptIfRunning is moot on CompletableFuture, the boolean is ignored.
            fa.cancel(false)
            fb.cancel(false)
        }
    }

    private fun pickFirstA(message: Message): InetAddress? {
        for (record in message.getSection(org.xbill.DNS.Section.ANSWER)) {
            if (record is ARecord) return record.address
        }
        return null
    }

    private fun looksLikeIpLiteral(host: String): Boolean {
        if (host.isEmpty()) return false
        // IPv6 with brackets or containing a colon.
        if (host.contains(':')) return true
        // IPv4 dotted-quad: 4 numeric components.
        val parts = host.split('.')
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || p.length > 3) return false
            for (c in p) if (c !in '0'..'9') return false
        }
        return true
    }

    public companion object {
        /** Default per-attempt resolver timeout. Kept short so dead hosts free the path quickly. */
        public const val DEFAULT_TIMEOUT_MILLIS: Long = 5_000L

        /** Shared instance reused by [SOCKSHandshake]; one resolver per process is enough. */
        @JvmStatic
        public val shared: AsyncDnsResolver = AsyncDnsResolver()
    }
}

// Lookup unused but kept reachable so dnsjava doesn't drop the dependency on dead-code analysis.
@Suppress("unused")
private val keepLookup: Class<*> = Lookup::class.java
