package de.torsm.socks

import io.ktor.network.sockets.*
import io.ktor.util.cio.*
import io.ktor.utils.io.*
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer


internal val InetAddress.isSOCKS4a: Boolean
    get() = when (this) {
        is Inet4Address -> {
            val address = address
            address[0] == 0.toByte()
                    && address[1] == 0.toByte()
                    && address[2] == 0.toByte()
                    && address[3] != 0.toByte()
        }
        else -> false
    }

private val terminatorByte = ByteBuffer.wrap(byteArrayOf(0))


internal suspend fun ByteReadChannel.readNullTerminatedString(): String {
    val buffer = KtorDefaultPool.borrow()
    try {
        val builder = StringBuilder()

        while (true) {
            val bytesRead = readUntilDelimiter(terminatorByte, buffer)
            if (bytesRead == 0) break

            val array = ByteArray(bytesRead)
            buffer.position(0)
            buffer.get(array)
            buffer.clear()

            builder.append(String(array))
        }
        skipDelimiter(terminatorByte)
        return builder.toString()
    } finally {
        KtorDefaultPool.recycle(buffer)
    }
}


public inline fun <C : ReadWriteSocket, R> C.useWithChannels(
    autoFlush: Boolean = false,
    block: (C, ByteReadChannel, ByteWriteChannel) -> R
): R {
    val reader = openReadChannel()
    val writer = openWriteChannel(autoFlush)
    var cause: Throwable? = null
    return try {
        block(this, reader, writer)
    } catch (e: Throwable) {
        cause = e
        throw e
    } finally {
        reader.cancel(cause)
        writer.close(cause)
        close()
    }
}

internal fun InetSocketAddress.withPort(port: Int) = InetSocketAddress(hostname, port)

internal fun InetSocketAddress.toJavaInetAddress() = toJavaAddress() as java.net.InetSocketAddress
