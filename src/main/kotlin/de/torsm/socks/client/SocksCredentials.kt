package de.torsm.socks.client

/**
 * RFC 1929 username/password credentials for SOCKS5 sub-negotiation.
 *
 * Not a data class: the auto-generated [toString] would expose the password
 * in logs and stack traces.
 *
 * @param username 1..255 UTF-8 bytes (RFC 1929 ULEN range).
 * @param password 1..255 UTF-8 bytes (RFC 1929 PLEN range).
 * @throws IllegalArgumentException if either field is outside the 1..255 byte range.
 */
public class SocksCredentials(public val username: String, public val password: String) {
    init {
        require(username.toByteArray(Charsets.UTF_8).size in 1..255) {
            "username length must be 1..255 UTF-8 bytes"
        }
        require(password.toByteArray(Charsets.UTF_8).size in 1..255) {
            "password length must be 1..255 UTF-8 bytes"
        }
    }

    /** Returns username only - password is always redacted. */
    override fun toString(): String = "SocksCredentials(username=$username, password=***)"

    override fun equals(other: Any?): Boolean =
        other is SocksCredentials && username == other.username && password == other.password

    override fun hashCode(): Int = 31 * username.hashCode() + password.hashCode()
}
