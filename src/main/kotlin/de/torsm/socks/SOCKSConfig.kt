package de.torsm.socks

import io.ktor.network.sockets.*
import io.ktor.util.network.*

/**
 * [SOCKSServer] configuration
 *
 * @property allowSOCKS4 Whether the server should accept clients using SOCKS4, which doesn't support authentication
 * @property authenticationMethods List of supported [authentication methods][SOCKSAuthenticationMethod] for SOCKS5
 * @property networkAddress [NetworkAddress] the server should bind to
 * @property connectTimeoutMillis Upper bound on the outbound TCP `connect()` to the requested
 *   target (and on the `accept()` wait for a SOCKS BIND). The default of 120 s was the upstream
 *   hard-coded value; lower it for callers that proxy many concurrent flows to unreachable hosts
 *   so a single bad target cannot hold dial-state for two minutes.
 */
public class SOCKSConfig(
    public val allowSOCKS4: Boolean,
    public val authenticationMethods: List<SOCKSAuthenticationMethod>,
    public val networkAddress: InetSocketAddress,
    public val connectTimeoutMillis: Long = DEFAULT_CONNECT_TIMEOUT_MILLIS,
) {
    public companion object {
        /** Backwards-compatible default: matches the previous hard-coded `TIME_LIMIT`. */
        public const val DEFAULT_CONNECT_TIMEOUT_MILLIS: Long = 120_000L
    }
}

/**
 * Builder class for [SOCKSConfig]
 *
 * By default, a config created by this builder will [allow][allowSOCKS4] SOCKS4 clients.
 *
 * By assigning a non-null value to [networkAddress], the created config will use that address.
 * Otherwise a combination of [hostname] and [port] is used (`0.0.0.0:1080` by default).
 *
 * If [authenticationMethods] remains empty, the created config will allow clients to use [NoAuthentication].
 */
public class SOCKSConfigBuilder {
    public val authenticationMethods: MutableList<SOCKSAuthenticationMethod> = mutableListOf()

    public var allowSOCKS4: Boolean = true

    public var networkAddress: InetSocketAddress? = null

    public var hostname: String = "0.0.0.0"

    public var port: Int = 1080

    /** See [SOCKSConfig.connectTimeoutMillis]. */
    public var connectTimeoutMillis: Long = SOCKSConfig.DEFAULT_CONNECT_TIMEOUT_MILLIS

    public fun build(): SOCKSConfig = SOCKSConfig(
        allowSOCKS4,
        authenticationMethods.ifEmpty { mutableListOf(NoAuthentication) },
        networkAddress ?: InetSocketAddress(hostname, port),
        connectTimeoutMillis,
    )
}

public fun SOCKSConfigBuilder.addAuthenticationMethod(method: SOCKSAuthenticationMethod) {
    authenticationMethods.add(method)
}
