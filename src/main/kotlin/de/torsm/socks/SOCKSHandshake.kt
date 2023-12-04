package de.torsm.socks

import de.torsm.socks.SOCKSAddressType.*
import de.torsm.socks.SOCKSCommand.*
import de.torsm.socks.SOCKSVersion.SOCKS4
import de.torsm.socks.SOCKSVersion.SOCKS5
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory
import java.lang.Byte.toUnsignedInt
import java.lang.Short.toUnsignedInt
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

@Suppress("BlockingMethodInNonBlockingContext")
public class SOCKSHandshake(
    private val reader: ByteReadChannel,
    private val writer: ByteWriteChannel,
    private val config: SOCKSConfig,
    private val selector: SelectorManager
) {
    public lateinit var selectedVersion: SOCKSVersion
    public lateinit var hostSocket: Socket

    private val log = LoggerFactory.getLogger(javaClass)

    public suspend fun negotiate() {
        selectedVersion = reader.readVersion()
        when (selectedVersion) {
            SOCKS4 -> {
                if (!config.allowSOCKS4) {
                    sendFullReply(SOCKS4_REJECTED)
                    throw SOCKSException("SOCKS4 connection not allowed")
                }
            }
            SOCKS5 -> {
                handleAuthentication()
                // read version of SOCKS request
                check(reader.readVersion() == selectedVersion) { "Inconsistent SOCKS versions" }
            }
        }

        val request = receiveRequest()

        when (request.command) {
            CONNECT -> connect(request)
            BIND -> bind(request)
            UDP_ASSOCIATE -> {
                check(selectedVersion == SOCKS5) { "SOCKS4 does not support $UDP_ASSOCIATE" }
                sendFullReply(SOCKS5_UNSUPPORTED_COMMAND)
                throw SOCKSException("Unsupported command: $UDP_ASSOCIATE")
            }
        }
    }


    private suspend fun receiveRequest(): SOCKSRequest {
        val command: SOCKSCommand
        val address: InetAddress
        val port: Short

        when (selectedVersion) {
            SOCKS4 -> {
                command = reader.readCommand()
                port = reader.readShort()
                val ip = reader.readAddress()
                reader.readNullTerminatedString() // ignoring USERID field

                address = if (ip.isSOCKS4a) {
                    InetAddress.getByName(reader.readNullTerminatedString())
                } else {
                    ip
                }
            }
            SOCKS5 -> {
                command = reader.readCommand()
                reader.readByte() // reserved (RSV) field
                address = reader.readAddress()
                port = reader.readShort()
            }
        }

        return SOCKSRequest(command, address, toUnsignedInt(port))
    }

    private suspend fun handleAuthentication() {
        val methodsCount = toUnsignedInt(reader.readByte())
        val clientMethods = List(methodsCount) { toUnsignedInt(reader.readByte()) }
        val commonMethod = config.authenticationMethods.firstOrNull { it.code in clientMethods }

        if (commonMethod == null) {
            sendPartialReply(SOCKS5_NO_ACCEPTABLE_METHODS)
            throw SOCKSException("No common authentication method found")
        } else {
            sendPartialReply(commonMethod.code.toByte())
            commonMethod.negotiate(reader, writer)
        }
    }

    private suspend fun connect(request: SOCKSRequest) {
        val host = InetSocketAddress(request.destinationAddress.hostAddress, request.port)
        hostSocket = try {
            withTimeout(TIME_LIMIT) {
                aSocket(selector).tcp().connect(host)
            }
        } catch (e: Throwable) {
            sendFullReply(selectedVersion.unreachableHostCode)
            throw SOCKSException("Unreachable host: $host", e)
        }

        try {
            log.debug("Connected to {}", host)
            sendFullReply(selectedVersion.successCode, hostSocket.localAddress as InetSocketAddress)
        } catch (e: Throwable) {
            hostSocket.close()
            throw e
        }
    }

    private suspend fun bind(request: SOCKSRequest) {
        hostSocket = coroutineScope {
            val address = config.networkAddress.withPort(0)
            aSocket(selector).tcp().bind(address).use { serverSocket ->
                val socketJob = async {
                    try {
                        withTimeout(TIME_LIMIT) {
                            serverSocket.accept()
                        }
                    } catch (e: Throwable) {
                        sendFullReply(selectedVersion.unreachableHostCode)
                        throw SOCKSException("Host (${request.destinationAddress}) didn't connect to bound socket (${serverSocket.localAddress})", e)
                    }
                }
                sendFullReply(selectedVersion.successCode, serverSocket.localAddress as InetSocketAddress)
                socketJob.await()
            }
        }

        val hostAddress = hostSocket.remoteAddress as InetSocketAddress

        if (hostAddress.toJavaAddress() != request.destinationAddress) {
            sendFullReply(selectedVersion.connectionRefusedCode)
            hostSocket.close()
            throw SOCKSException("Incoming host address ($hostAddress) did not match requested host (${request.destinationAddress})")
        }

        try {
            log.debug("Host was bound: {}", hostAddress)
            sendFullReply(selectedVersion.successCode, hostAddress)
        } catch (e: Exception) {
            hostSocket.close()
            throw e
        }
    }

    private suspend fun sendPartialReply(code: Byte, writeAdditionalData: suspend BytePacketBuilder.() -> Unit = {}) {
        writer.writePacket {
            writeByte(selectedVersion.replyVersion)
            writeByte(code)
            writeAdditionalData()
        }
        writer.flush()
    }

    private suspend fun sendFullReply(code: Byte, address: InetSocketAddress = emptyAddress) {
        sendPartialReply(code) {
            if (selectedVersion == SOCKS5) writeByte(SOCKS5_RESERVED)
            writeAddress(address)
        }
    }



    private suspend fun ByteReadChannel.readVersion(): SOCKSVersion {
        val versionNumber = readByte()
        return SOCKSVersion.byCode(versionNumber)
    }

    private suspend fun ByteReadChannel.readCommand(): SOCKSCommand {
        val code = readByte()
        return SOCKSCommand.byCode(code)
    }

    private suspend fun ByteReadChannel.readAddress(): InetAddress {
        val addressType = when (selectedVersion) {
            SOCKS4 -> IPV4
            SOCKS5 -> SOCKSAddressType.byCode(readByte())
        }
        return when (addressType) {
            IPV4 -> {
                val data = readPacket(4)
                Inet4Address.getByAddress(data.readBytes())
            }
            IPV6 -> {
                val data = readPacket(16)
                Inet6Address.getByAddress(data.readBytes())
            }
            HOSTNAME -> {
                val size = toUnsignedInt(readByte())
                val data = readPacket(size)
                InetAddress.getByName(data.readBytes().decodeToString())
            }
        }
    }

    private fun BytePacketBuilder.writeAddress(address: InetSocketAddress) {
        val port = address.port.toShort()
        val ip = address.toJavaInetAddress().address
        when (selectedVersion) {
            SOCKS4 -> {
                check(ip is Inet4Address || ip.isAnyLocalAddress) { "Expecting IPv4 address for SOCKS4" }
                writeShort(port)
                writeFully(ip.address, length = 4)
            }
            SOCKS5 -> {
                when (ip) {
                    is Inet4Address -> writeByte(IPV4.code)
                    is Inet6Address -> writeByte(IPV6.code)
                    else -> error("Unknown InetAddress type: ${ip.javaClass}")
                }
                writeFully(ip.address)
                writeShort(port)
            }
        }
    }

    private data class SOCKSRequest(
        val command: SOCKSCommand,
        val destinationAddress: InetAddress,
        val port: Int
    )
}

private const val TIME_LIMIT = 120000.toLong()
private const val SOCKS4_REJECTED = 91.toByte()
private const val SOCKS5_RESERVED = 0.toByte()
private const val SOCKS5_UNSUPPORTED_COMMAND = 7.toByte()
private const val SOCKS5_NO_ACCEPTABLE_METHODS = 0xFF.toByte()
private val emptyAddress = InetSocketAddress("0.0.0.0", 0)
