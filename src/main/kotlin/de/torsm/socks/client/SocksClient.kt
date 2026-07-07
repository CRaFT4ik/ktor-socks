package de.torsm.socks.client

import de.torsm.socks.protocol.AddressCodec
import de.torsm.socks.protocol.RFC1929Codec
import de.torsm.socks.protocol.SOCKSCommand
import de.torsm.socks.protocol.SocksMethodCode
import de.torsm.socks.protocol.SocksProtocolException
import de.torsm.socks.protocol.SocksReplyCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.ConnectException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Coroutine-friendly SOCKS5 client. Performs CONNECT-phase negotiation on [Dispatchers.IO]
 * and returns a ready-to-use [Socks5UdpAssociateSocket] on success.
 *
 * Strict offer policy: without credentials only NO_AUTH is offered; with credentials
 * only USER_PASS is offered. Any other method selected by the server is a
 * [SocksClientException.ProtocolViolation].
 *
 * @param config proxy address, credentials, and timeout settings.
 * @param udpBindFactory factory that creates the local UDP socket; injectable for testing.
 *   Receives the [InetAddress] destination hint (the address the caller will communicate
 *   with through the relay). Default: binds to any port on loopback.
 */
public class SocksClient(
    private val config: SocksClientConfig,
    private val udpBindFactory: (InetAddress) -> DatagramSocket = { DatagramSocket(0, InetAddress.getLoopbackAddress()) },
) {

    /**
     * Establishes the SOCKS5 UDP ASSOCIATE session.
     *
     * Performs TCP connect, method negotiation, optional RFC 1929 auth, and the
     * UDP ASSOCIATE command in [Dispatchers.IO]. The returned socket wraps both the
     * UDP relay channel and the TCP control connection that must stay open for the
     * duration of the relay.
     *
     * @param destination the IP address the caller will send datagrams to through the relay.
     *   Used as the BND.ADDR hint in the ASSOCIATE request and for address-mismatch detection.
     * @return connected [Socks5UdpAssociateSocket] ready for send/receive.
     * @throws SocksClientException.ProxyUnreachable if the TCP connection to the proxy fails.
     * @throws SocksClientException.NotSocks5Proxy if the proxy is not SOCKS5.
     * @throws SocksClientException.NoSharedMethod if no method is mutually acceptable.
     * @throws SocksClientException.AuthFailed if RFC 1929 auth is rejected.
     * @throws SocksClientException.ProtocolViolation on any structural protocol error.
     * @throws SocksClientException on any other SOCKS5-level failure.
     */
    public suspend fun udpAssociate(destination: InetAddress): Socks5UdpAssociateSocket {
        val tcp = Socket()
        try {
            withContext(Dispatchers.IO) {
                tcp.connect(InetSocketAddress(config.proxyHost, config.proxyPort), config.connectTimeoutMillis.toInt())
            }
        } catch (e: ConnectException) {
            runCatching { tcp.close() }
            throw SocksClientException.ProxyUnreachable(e)
        } catch (e: NoRouteToHostException) {
            runCatching { tcp.close() }
            throw SocksClientException.ProxyUnreachable(e)
        } catch (e: SocketTimeoutException) {
            runCatching { tcp.close() }
            throw SocksClientException.ProxyUnreachable(e)
        } catch (e: IOException) {
            runCatching { tcp.close() }
            throw SocksClientException.ProxyUnreachable(e)
        }

        val localUdp = udpBindFactory(destination)

        // NF-3: wrap all steps after bind; on any throw close both resources before rethrowing.
        try {
            tcp.soTimeout = config.handshakeTimeoutMillis.toInt()

            val din = DataInputStream(tcp.getInputStream())
            val dout = DataOutputStream(tcp.getOutputStream())

            withContext(Dispatchers.IO) {
                negotiate(din, dout)
            }

            val relay = withContext(Dispatchers.IO) {
                sendUdpAssociate(din, dout, tcp, localUdp)
            }

            // Reset to infinite read after handshake succeeds (TCP-control keepalive).
            tcp.soTimeout = 0
            return Socks5UdpAssociateSocket(localUdp, relay, tcp, destination)
        } catch (t: Throwable) {
            runCatching { localUdp.close() }
            runCatching { tcp.close() }
            when (t) {
                is SocksClientException -> throw t
                is IOException -> throw SocksClientException.ProxyTcpClosed(t)
                else -> throw t
            }
        }
    }

    /**
     * Blocking method negotiation (NO_AUTH or USER_PASS only).
     *
     * Must be called from a thread that can block (e.g. inside [withContext(Dispatchers.IO)]).
     */
    private fun negotiate(din: DataInputStream, dout: DataOutputStream) {
        val offered: List<SocksMethodCode> = if (config.credentials != null) {
            listOf(SocksMethodCode.UserPass)
        } else {
            listOf(SocksMethodCode.NoAuth)
        }
        val offerCodes = byteArrayOf(offered[0].code)
        dout.write(byteArrayOf(0x05.toByte(), offerCodes.size.toByte()))
        dout.write(offerCodes)
        dout.flush()

        val ver = din.readByte()
        if (ver != 0x05.toByte()) throw SocksClientException.NotSocks5Proxy(ver)
        val chosen = din.readByte()
        val method = SocksMethodCode.of(chosen)
        if (method is SocksMethodCode.NoAcceptable) throw SocksClientException.NoSharedMethod()
        if (offered.none { it.code == chosen }) {
            throw SocksClientException.ProtocolViolation(
                "server selected method 0x%02X not offered".format(chosen.toInt() and 0xFF)
            )
        }
        if (method is SocksMethodCode.UserPass) {
            val creds = config.credentials
                ?: throw SocksClientException.ProtocolViolation("server chose UserPass but no credentials configured")
            dout.write(RFC1929Codec.encodeRequest(creds.username, creds.password))
            dout.flush()
            val resp = ByteArray(2).also { din.readFully(it) }
            val ok = try {
                RFC1929Codec.parseResponse(resp)
            } catch (e: SocksProtocolException) {
                throw SocksClientException.ProtocolViolation(e.message ?: "malformed RFC 1929 response")
            }
            if (!ok) throw SocksClientException.AuthFailed()
        }
    }

    /**
     * Blocking UDP ASSOCIATE request. Sends the command and reads the BND address/port.
     *
     * Must be called from a thread that can block (e.g. inside [withContext(Dispatchers.IO)]).
     *
     * @return the relay endpoint to which datagrams must be sent.
     */
    private fun sendUdpAssociate(
        din: DataInputStream,
        dout: DataOutputStream,
        tcp: Socket,
        localUdp: DatagramSocket,
    ): InetSocketAddress {
        val hintAddr = localUdp.localAddress
        val addrBlock = AddressCodec.writeToByteArray(hintAddr, localUdp.localPort)
        val req = ByteArray(3 + addrBlock.size)
        req[0] = 0x05.toByte()
        req[1] = SOCKSCommand.UDP_ASSOCIATE.code
        req[2] = 0x00.toByte()
        addrBlock.copyInto(req, 3)
        dout.write(req)
        dout.flush()

        val head = ByteArray(4).also { din.readFully(it) }
        if (head[0] != 0x05.toByte()) throw SocksClientException.NotSocks5Proxy(head[0])
        val rep = SocksReplyCode.of(head[1])
        // head[2] is RSV - ignored per RFC 1928 section 6
        if (rep != SocksReplyCode.SUCCEEDED) throw SocksClientException.forReply(rep)
        val atyp = head[3]
        val addr: InetAddress = when (atyp) {
            0x01.toByte() -> InetAddress.getByAddress(ByteArray(4).also { din.readFully(it) })
            0x04.toByte() -> InetAddress.getByAddress(ByteArray(16).also { din.readFully(it) })
            0x03.toByte() -> {
                // Consume the domain bytes to keep the TCP stream in sync, then reject.
                val n = din.readUnsignedByte()
                din.readFully(ByteArray(n))
                throw SocksClientException.ProtocolViolation(
                    "DOMAIN BND.ADDR not supported; proxy must return numeric address"
                )
            }
            else -> throw SocksClientException.ProtocolViolation(
                "unknown ATYP=0x%02X in ASSOCIATE reply".format(atyp.toInt() and 0xFF)
            )
        }
        val port = (din.readUnsignedByte() shl 8) or din.readUnsignedByte()
        // Per RFC 1928 section 6: BND.ADDR of 0.0.0.0 (or ::) means use the TCP peer address.
        val relayHost = if (addr.isAnyLocalAddress) {
            (tcp.remoteSocketAddress as InetSocketAddress).address
        } else addr
        return InetSocketAddress(relayHost, port)
    }
}
