package de.torsm.socks.client

/**
 * Configuration for [SocksClient].
 *
 * @param proxyHost hostname or IP of the SOCKS5 proxy.
 * @param proxyPort TCP port of the SOCKS5 proxy; must be in 1..65535.
 * @param credentials optional RFC 1929 username/password; null means NO_AUTH only.
 * @param connectTimeoutMillis TCP connect timeout in milliseconds; range 100..60000.
 * @param handshakeTimeoutMillis socket read timeout during the SOCKS5 handshake in milliseconds;
 *   reset to zero (infinite) after handshake succeeds; range 100..60000.
 * @throws IllegalArgumentException if any field violates its constraint.
 */
public data class SocksClientConfig(
    val proxyHost: String,
    val proxyPort: Int,
    val credentials: SocksCredentials? = null,
    val connectTimeoutMillis: Long = 5_000L,
    val handshakeTimeoutMillis: Long = 10_000L,
) {
    init {
        require(proxyHost.isNotBlank()) { "proxyHost required" }
        require(proxyPort in 1..65_535) { "proxyPort out of range: $proxyPort" }
        require(connectTimeoutMillis in 100L..60_000L) {
            "connectTimeoutMillis must be in 100..60000, was $connectTimeoutMillis"
        }
        require(handshakeTimeoutMillis in 100L..60_000L) {
            "handshakeTimeoutMillis must be in 100..60000, was $handshakeTimeoutMillis"
        }
    }
}
