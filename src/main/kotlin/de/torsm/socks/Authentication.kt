package de.torsm.socks

import io.ktor.utils.io.*
import io.ktor.utils.io.core.*


interface SOCKSAuthenticationMethod {
    val code: Byte

    suspend fun negotiate(reader: ByteReadChannel, writer: ByteWriteChannel)
}


object NoAuthentication : SOCKSAuthenticationMethod {
    override val code: Byte = 0

    override suspend fun negotiate(reader: ByteReadChannel, writer: ByteWriteChannel) {}
}


abstract class UsernamePasswordAuthentication : SOCKSAuthenticationMethod {
    override val code: Byte = 2

    override suspend fun negotiate(reader: ByteReadChannel, writer: ByteWriteChannel) {
        val version = reader.readByte()
        if (version != VERSION) {
            throw SOCKSException("Invalid Username/Password authentication version: $version")
        }

        val usernameSize = reader.readByte().toInt()
        val username = reader.readPacket(usernameSize).readBytes().decodeToString()
        val passwordSize = reader.readByte().toInt()
        val password = reader.readPacket(passwordSize).readBytes().decodeToString()

        if (verify(username, password)) {
            writer.writeResponse(SUCCESS)
        } else {
            writer.writeResponse(FAILURE)
            throw SOCKSException("Username/Password authentication failed")
        }
    }

    private suspend fun ByteWriteChannel.writeResponse(status: Byte) {
        writePacket {
            writeByte(VERSION)
            writeByte(status)
        }
        flush()
    }

    abstract fun verify(username: String, password: String): Boolean

    companion object {
        private const val VERSION = 1.toByte()
        private const val SUCCESS = 0.toByte()
        private const val FAILURE = 1.toByte()
    }
}
