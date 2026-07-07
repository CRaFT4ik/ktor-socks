package de.torsm.socks.server

import io.ktor.network.selector.SelectorManager

internal class SocksUdpRelay(
    private val handshake: SOCKSHandshake,
    private val request: SOCKSHandshake.RelayRequest,
    private val config: SOCKSConfig,
    private val selector: SelectorManager,
) {
    internal suspend fun run(): Unit = TODO("SocksUdpRelay implemented in Task 9")
}
