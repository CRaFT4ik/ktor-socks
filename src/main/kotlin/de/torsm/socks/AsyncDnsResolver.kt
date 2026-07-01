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
import org.xbill.DNS.ResolverConfig
import org.xbill.DNS.SimpleResolver
import org.xbill.DNS.Type
import org.xbill.DNS.hosts.HostsFileParser
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Non-blocking DNS resolver for hostnames received by the SOCKS5 handshake.
 *
 * Resolution follows POSIX Name Service Switch semantics (`files -> dns`): the OS hosts file
 * (`/etc/hosts` on unix, `%SystemRoot%\System32\drivers\etc\hosts` on windows) is consulted
 * first and wins deterministically when the requested host has an entry. Only when the hosts
 * file has no match does the DNS race run. This matches the behaviour users expect from `curl`
 * and `getaddrinfo` and lets intranet overrides (e.g. an internal ingress mapped by hand) beat
 * whatever the raw DNS servers would return.
 *
 * When the hosts file has no entry, three upstream resolvers are queried in parallel and
 * whichever answers first wins: Cloudflare 1.1.1.1, Google 8.8.8.8, and the host's
 * currently-configured system DNS server (read from the OS network stack via dnsjava's
 * [ResolverConfig], refreshed at the cadence defined by [SYSTEM_DNS_REFRESH_INTERVAL_MILLIS]).
 * The system entry lets split-horizon intranet names (corporate hosts the public resolvers do
 * not know) succeed without forcing every query through a slow corporate DNS. When the watcher
 * has no system server yet (fresh process, between refreshes after the OS removed all servers),
 * the race runs with the two public resolvers only.
 *
 * Critically, the system DNS is queried over UDP via dnsjava NIO exactly like the public
 * resolvers; we never call [InetAddress.getByName] just to pick up the OS resolver, since that
 * call blocks a JVM thread on getaddrinfo for the full system timeout. The watcher only reads
 * the OS-configured server IPs (cheap, non-blocking) and feeds them into the same async race.
 *
 * If no path answers within [timeoutMillis], the JDK system resolver is consulted off
 * [Dispatchers.IO] as a last-chance fallback so even names that need OS-level resolution hooks
 * (mDNS, NSS plug-ins) still resolve. The fallback is bounded by [timeoutMillis] so a hung
 * getaddrinfo cannot pin the path indefinitely.
 *
 * Threading contract: [resolve] suspends but never blocks the caller's thread on socket I/O.
 * dnsjava's NIO event loop runs on its own daemon threads. Hosts file I/O is wrapped in
 * [Dispatchers.IO]; dnsjava's [HostsFileParser] caches the parsed file by mtime so only the
 * first lookup pays the sub-millisecond read cost.
 *
 * On NXDOMAIN every path throws [UnknownHostException]. Other transient failures (timeout,
 * NoRouteToHost) also surface as [UnknownHostException] so the SOCKS5 server returns a sane
 * REP code to the client.
 *
 * @property timeoutMillis per-attempt timeout for each upstream resolver (race) and for the
 *   system fallback combined; total wall-clock is bounded by 2x [timeoutMillis] in the worst
 *   case (race timeout + system fallback timeout).
 * @property systemDnsWatcher source of system DNS server addresses; tests inject a fixed or
 *   empty watcher to control the race composition. Defaults to a shared watcher that polls
 *   the OS every [SYSTEM_DNS_REFRESH_INTERVAL_MILLIS].
 * @property hostsFile parser for the OS hosts file. Defaults to dnsjava's default-constructor
 *   parser which picks the platform-appropriate path. Tests inject a parser pointed at a
 *   fixture file to control what wins the pre-race lookup.
 */
public class AsyncDnsResolver(
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
    private val systemDnsWatcher: SystemDnsWatcher = SystemDnsWatcher.shared,
    private val hostsFile: HostsFileParser = HostsFileParser(),
) {

    private val log = LoggerFactory.getLogger(javaClass)

    init {
        // Announce hosts-file registration at INFO, symmetric to dnsjava's own
        // "Added /1.1.1.1:53 to nameservers" line for the DNS resolvers. Without this, operators
        // reading startup logs cannot tell that hosts entries are being consulted before the DNS
        // race. Path is read via reflection because HostsFileParser exposes no getter; on failure
        // we log a generic message so a dnsjava field rename cannot break startup.
        val path = try {
            val field = HostsFileParser::class.java.getDeclaredField("path")
            field.isAccessible = true
            field.get(hostsFile)?.toString()
        } catch (_: Throwable) {
            null
        }
        if (path != null) {
            log.info("Hosts file registered as first-priority resolver: {}", path)
        } else {
            log.info("Hosts file registered as first-priority resolver (default OS hosts file)")
        }
    }

    private data class PublicResolvers(val cloudflare: SimpleResolver, val google: SimpleResolver)

    private val publicResolvers: AtomicReference<PublicResolvers?> = AtomicReference(null)

    private fun publicResolvers(): PublicResolvers? {
        publicResolvers.get()?.let { return it }
        return try {
            val cf = SimpleResolver("1.1.1.1").apply { timeout = Duration.ofMillis(timeoutMillis) }
            val go = SimpleResolver("8.8.8.8").apply { timeout = Duration.ofMillis(timeoutMillis) }
            val built = PublicResolvers(cf, go)
            publicResolvers.compareAndSet(null, built)
            publicResolvers.get()
        } catch (t: Throwable) {
            // Resolver construction itself failed (rare: bad address literal). Surface as null;
            // the resolve() path will fall back to the system resolver.
            log.warn("AsyncDnsResolver init failed, will fall back to system resolver: {}", t.toString())
            null
        }
    }

    /**
     * Builds a one-shot [SimpleResolver] for the current system DNS server, or null when the
     * watcher has nothing to offer (no servers configured yet or a transient read failure).
     *
     * A fresh resolver per resolve() call keeps the watcher refresh cycle truly observable: a
     * VPN that just came up and changed the system DNS lands in the very next race instead of
     * waiting for a long-lived resolver instance to expire.
     */
    private fun systemResolverOrNull(): SimpleResolver? {
        val server = systemDnsWatcher.currentServer() ?: return null
        return try {
            SimpleResolver(server).apply { timeout = Duration.ofMillis(timeoutMillis) }
        } catch (t: Throwable) {
            log.debug("Failed to construct system DNS resolver for {}: {}", server, t.toString())
            null
        }
    }

    /**
     * Resolves [host] to an [InetAddress] without blocking the caller's coroutine thread.
     *
     * Resolution order:
     *   1. Already an IPv4/IPv6 literal: [InetAddress.getByName] short-circuits, no DNS lookup.
     *   2. OS hosts file (`/etc/hosts` on unix, windows equivalent): if the name has an entry
     *      it wins immediately and no DNS traffic is generated. Matches POSIX nsswitch
     *      `files -> dns` order.
     *   3. Race the OS-configured system DNS (when available) plus 1.1.1.1 plus 8.8.8.8 over UDP
     *      via dnsjava NIO; whichever returns an A record first wins.
     *   4. If every racer times out or errors, fall back to the system resolver on
     *      [Dispatchers.IO] (so a slow getaddrinfo still does not pin the caller's thread).
     *
     * @throws UnknownHostException when no path produced an address.
     */
    public suspend fun resolve(host: String): InetAddress {
        // IP literals (a.b.c.d / IPv6) are not DNS names. Short-circuit via the JDK; this only
        // parses the literal, no resolver socket is touched.
        if (looksLikeIpLiteral(host)) {
            return InetAddress.getByName(host)
        }

        // Hosts file wins over DNS when an entry is present. dnsjava caches the parsed file by
        // mtime, so this is a memory lookup after the first call and picks up edits when the
        // user re-saves the file.
        hostsFileLookup(host)?.let { return it }

        val publics = publicResolvers()
        val system = systemResolverOrNull()
        val racers: List<Resolver> = buildList {
            if (system != null) add(system)
            if (publics != null) {
                add(publics.cloudflare)
                add(publics.google)
            }
        }
        if (racers.isNotEmpty()) {
            val raced = withTimeoutOrNull(timeoutMillis) {
                raceAsync(host, racers)
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

    /**
     * Looks up [host] in the OS hosts file via dnsjava's [HostsFileParser].
     *
     * Returns the mapped address when the file has a matching A record, null when the file has
     * no entry for [host] or any read/parse error occurs. Errors are swallowed intentionally so
     * a corrupt or unreadable hosts file cannot break normal DNS resolution; the caller falls
     * through to the DNS race in that case.
     *
     * File I/O is wrapped in [Dispatchers.IO] to keep the caller thread free. dnsjava caches
     * the parsed file by mtime, so only the first call in each edit cycle pays the actual read
     * cost (sub-millisecond for a typical hosts file).
     */
    private suspend fun hostsFileLookup(host: String): InetAddress? = withContext(Dispatchers.IO) {
        try {
            val name = Name.fromString(if (host.endsWith('.')) host else "$host.")
            val addr = hostsFile.getAddressForHost(name, Type.A).orElse(null)
            if (addr != null) {
                // DEBUG per hit so operators can attribute a resolution to /etc/hosts vs DNS. Kept
                // at DEBUG because a busy proxy could otherwise flood the log; the INFO init line
                // already proves the resolver is live.
                log.debug("Resolved {} via hosts file: {}", host, addr.hostAddress)
            }
            addr
        } catch (_: Throwable) {
            null
        }
    }

    private suspend fun raceAsync(host: String, resolvers: List<Resolver>): InetAddress? {
        val name = try {
            Name.fromString(if (host.endsWith('.')) host else "$host.")
        } catch (_: Throwable) {
            return null
        }
        val query = Message.newQuery(org.xbill.DNS.Record.newRecord(name, Type.A, org.xbill.DNS.DClass.IN))

        // dnsjava sendAsync returns a CompletionStage<Message>; race them with anyOf, then fall
        // back to the remaining futures if the first to complete failed.
        val futures: List<CompletableFuture<Message>> =
            resolvers.map { it.sendAsync(query).toCompletableFuture() }
        try {
            // anyOf: the first to complete (success OR failure) wins. We accept a successful
            // result immediately; if the winner failed, walk the remaining futures for a salvage.
            val winner = try {
                val any = CompletableFuture.anyOf(*futures.toTypedArray()).await()
                any as? Message
            } catch (_: Throwable) {
                null
            }
            val msg = winner ?: salvage(futures) ?: return null
            return pickFirstA(msg)
        } finally {
            // Cancel any future that did not produce the returned answer so the dnsjava NIO worker
            // drops its pending UDP state instead of waiting for its own timeout.
            futures.forEach { it.cancel(false) }
        }
    }

    /**
     * Walks the futures that did NOT win [CompletableFuture.anyOf] and returns the first one
     * that already completed successfully, awaiting up to the remaining race budget on the rest.
     *
     * This salvage path matters when the fastest racer is a misconfigured server that returns
     * REFUSED or SERVFAIL: it completes first (so wins anyOf) but produced no answer. Without
     * salvage the slower-but-correct racer's result would be discarded by the outer finally.
     */
    private suspend fun salvage(futures: List<CompletableFuture<Message>>): Message? {
        for (f in futures) {
            if (f.isDone && !f.isCompletedExceptionally && !f.isCancelled) {
                return try { f.get() } catch (_: Throwable) { null }
            }
        }
        for (f in futures) {
            if (f.isDone) continue
            try {
                return f.await()
            } catch (_: Throwable) {
                // try the next
            }
        }
        return null
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

        /**
         * Refresh cadence for [SystemDnsWatcher]'s view of the OS-configured DNS servers. 90 s
         * is short enough to pick up a VPN-pushed DNS change within a typical user-perceptible
         * window yet long enough to keep the per-cycle DEBUG log block (search-paths plus
         * nameservers, four lines per refresh on Windows) from dominating the production log.
         */
        public const val SYSTEM_DNS_REFRESH_INTERVAL_MILLIS: Long = 90_000L

        /** Shared instance reused by [SOCKSHandshake]; one resolver per process is enough. */
        @JvmStatic
        public val shared: AsyncDnsResolver = AsyncDnsResolver()
    }
}

/**
 * Background poller that publishes the host's currently-configured DNS server IP so the resolver
 * race can include it without blocking on the OS resolver itself.
 *
 * Why a watcher and not a per-resolve read: dnsjava's [ResolverConfig.refresh] walks the OS
 * configuration (Windows IPHlpAPI / Linux /etc/resolv.conf) and that walk is comparatively
 * expensive and not designed to be called per query. A daemon thread polls every
 * [intervalMillis] and publishes the first usable server into an atomic reference; resolvers
 * read that reference lock-free.
 *
 * Single server is published intentionally: corporate networks routinely list several internal
 * DNS servers and any one of them will know the corporate names. Picking the first keeps the
 * race width predictable (one system racer + two public).
 *
 * @param intervalMillis poll cadence. Default 90 s strikes a balance between picking up a new
 *   VPN-pushed DNS quickly and not waking the JVM unnecessarily.
 * @param read function that returns the current OS DNS server list. Tests override to inject
 *   a deterministic value; production uses [readSystemDns].
 */
public class SystemDnsWatcher(
    private val intervalMillis: Long = AsyncDnsResolver.SYSTEM_DNS_REFRESH_INTERVAL_MILLIS,
    private val read: () -> List<InetSocketAddress> = ::readSystemDns,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    private val current: AtomicReference<InetSocketAddress?> = AtomicReference(null)

    @Volatile
    private var started: Boolean = false

    /**
     * Returns the most recently observed system DNS server, or null when no usable server has
     * been read yet. Lock-free: safe to call from any thread on any resolve path.
     */
    public fun currentServer(): InetSocketAddress? = current.get()

    /**
     * Forces an immediate re-read of the OS-configured DNS servers. Used by tests to avoid the
     * scheduled poll wait; in production the daemon poller handles refreshes.
     */
    public fun refreshNow() {
        runCatching {
            val first = read().firstOrNull()
            current.set(first)
        }.onFailure { log.debug("SystemDnsWatcher refresh failed: {}", it.toString()) }
    }

    /**
     * Starts the background refresh loop. Idempotent: a second call is a no-op so the [shared]
     * watcher can be started safely from multiple resolver instances.
     */
    public fun start() {
        if (started) return
        synchronized(this) {
            if (started) return
            // Eager first read so the very first resolve() already has a server when one is
            // configured; the loop then keeps it in sync with VPN-up / network-change events.
            refreshNow()
            executor.scheduleWithFixedDelay(
                { refreshNow() },
                intervalMillis,
                intervalMillis,
                TimeUnit.MILLISECONDS,
            )
            started = true
        }
    }

    private val executor by lazy {
        Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "ktor-socks-system-dns-watcher").apply { isDaemon = true }
        }
    }

    public companion object {
        /**
         * Process-wide singleton used by [AsyncDnsResolver.shared]. Eagerly started here so the
         * first resolve() already benefits from a populated system DNS without a separate
         * initialization step at every call site.
         */
        @JvmStatic
        public val shared: SystemDnsWatcher = SystemDnsWatcher().also { it.start() }

        /**
         * Reads the OS-configured DNS server list via dnsjava's [ResolverConfig]. Cross-platform:
         * Windows IPHlpAPI (via JNA bundled with dnsjava) and Linux /etc/resolv.conf are both
         * handled by the same call. Returns an empty list on any failure so the caller can
         * gracefully fall back to public resolvers.
         */
        public fun readSystemDns(): List<InetSocketAddress> = try {
            ResolverConfig.refresh()
            ResolverConfig.getCurrentConfig().servers().orEmpty()
        } catch (_: Throwable) {
            emptyList()
        }
    }
}

// Lookup unused but kept reachable so dnsjava doesn't drop the dependency on dead-code analysis.
@Suppress("unused")
private val keepLookup: Class<*> = Lookup::class.java
