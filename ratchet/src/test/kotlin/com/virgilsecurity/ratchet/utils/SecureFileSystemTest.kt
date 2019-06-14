package com.virgilsecurity.ratchet.utils

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.*


class SecureFileSystemTest {
    val identity = UUID.randomUUID().toString()
    val path = createTempDir().toPath()
    lateinit var secureFileSystem: SecureFileSystem

    @BeforeAll
    fun setup() {
        secureFileSystem = SecureFileSystem(identity, path, null)
    }

    @Test
    fun write_then_read() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        val dataFromFile = secureFileSystem.read(name)
        assertNotNull(dataFromFile)
        assertArrayEquals(data, dataFromFile)
    }

    @Test
    fun write_then_deleteFile() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        assertTrue(secureFileSystem.read(name).isNotEmpty())
        secureFileSystem.delete(name)
        assertTrue(secureFileSystem.read(name).isEmpty())
    }

    @Test
    fun write_then_deleteDir() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        assertTrue(secureFileSystem.read(name).isNotEmpty())
        secureFileSystem.deleteDir()
        assertTrue(secureFileSystem.read(name).isEmpty())
    }
}
