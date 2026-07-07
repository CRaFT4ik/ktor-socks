package de.torsm.socks.server

import de.torsm.socks.protocol.SOCKSCommand
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
 * @property commands Set of SOCKS commands the server accepts. Defaults to [SOCKSCommand.CONNECT]
 *   only. Add [SOCKSCommand.UDP_ASSOCIATE] to enable UDP relay. Must not be empty.
 * @property udpIdleAssociationTimeoutSeconds Seconds of UDP inactivity before the relay tears
 *   down. Valid range is 1..86400 when [SOCKSCommand.UDP_ASSOCIATE] is in [commands] (validated
 *   at [SOCKSConfigBuilder.build] time). Values outside that range risk an infinite loop (zero)
 *   or Long overflow in nanosecond arithmetic (> 86400). Only relevant when
 *   [SOCKSCommand.UDP_ASSOCIATE] is in [commands].
 */
public class SOCKSConfig(
    public val allowSOCKS4: Boolean,
    public val authenticationMethods: List<SOCKSAuthenticationMethod>,
    public val networkAddress: InetSocketAddress,
    public val connectTimeoutMillis: Long = DEFAULT_CONNECT_TIMEOUT_MILLIS,
    public val commands: Set<SOCKSCommand> = setOf(SOCKSCommand.CONNECT),
    public val udpIdleAssociationTimeoutSeconds: Long = 300L,
) {
    init {
        require(commands.isNotEmpty()) { "commands must not be empty" }
    }

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

    /**
     * Set of SOCKS commands the server accepts. Must not be empty.
     * Defaults to [SOCKSCommand.CONNECT] only.
     */
    public var commands: Set<SOCKSCommand> = setOf(SOCKSCommand.CONNECT)
        set(value) {
            require(value.isNotEmpty()) { "commands must not be empty" }
            field = value
        }

    /**
     * See [SOCKSConfig.udpIdleAssociationTimeoutSeconds].
     * Must be in 1..86400 when [SOCKSCommand.UDP_ASSOCIATE] is in [commands].
     */
    public var udpIdleAssociationTimeoutSeconds: Long = 300L

    public fun build(): SOCKSConfig {
        if (SOCKSCommand.UDP_ASSOCIATE in commands) {
            require(udpIdleAssociationTimeoutSeconds in 1L..86400L) {
                "udpIdleAssociationTimeoutSeconds must be in 1..86400 when UDP_ASSOCIATE is enabled, " +
                    "got $udpIdleAssociationTimeoutSeconds"
            }
        }
        val cfg = SOCKSConfig(
            allowSOCKS4,
            authenticationMethods.ifEmpty { mutableListOf(NoAuthentication) },
            networkAddress ?: InetSocketAddress(hostname, port),
            connectTimeoutMillis,
            commands,
            udpIdleAssociationTimeoutSeconds,
        )
        warnIfInsecureCombination(cfg)
        return cfg
    }

    private companion object {
        private val log = org.slf4j.LoggerFactory.getLogger(SOCKSConfigBuilder::class.java)

        fun warnIfInsecureCombination(cfg: SOCKSConfig) {
            if (SOCKSCommand.UDP_ASSOCIATE in cfg.commands
                && NoAuthentication in cfg.authenticationMethods
                && !(cfg.networkAddress.toJavaAddress() as java.net.InetSocketAddress).address.isLoopbackAddress
            ) {
                log.warn(
                    "SECURITY: UDP_ASSOCIATE enabled with NoAuthentication on non-loopback address {}; open UDP relay for anyone. Ensure firewall protection.",
                    cfg.networkAddress
                )
            }
            if (cfg.allowSOCKS4 && SOCKSCommand.UDP_ASSOCIATE in cfg.commands) {
                log.warn(
                    "SOCKS4 clients cannot use UDP_ASSOCIATE (SOCKS5 only); allowSOCKS4=true with UDP_ASSOCIATE in commands has no effect for SOCKS4 clients."
                )
            }
        }
    }
}

public fun SOCKSConfigBuilder.addAuthenticationMethod(method: SOCKSAuthenticationMethod) {
    authenticationMethods.add(method)
}
