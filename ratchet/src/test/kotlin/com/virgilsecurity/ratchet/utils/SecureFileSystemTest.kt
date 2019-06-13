package com.virgilsecurity.ratchet.utils

import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.*


class SecureFileSystemTest {
    val identity = UUID.randomUUID().toString()
    val path = createTempDir().toPath()
    lateinit var secureFileSystem: SecureFileSystem

    @Before
    fun setup() {
        secureFileSystem = SecureFileSystem(identity, path, null)
    }

    @Test
    fun write_then_read() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        val dataFromFile = secureFileSystem.read(name)
        Assert.assertNotNull(dataFromFile)
        Assert.assertArrayEquals(data, dataFromFile)
    }

    @Test
    fun write_then_deleteFile() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        Assert.assertTrue(secureFileSystem.read(name).isNotEmpty())
        secureFileSystem.delete(name)
        Assert.assertTrue(secureFileSystem.read(name).isEmpty())
    }

    @Test
    fun write_then_deleteDir() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        Assert.assertTrue(secureFileSystem.read(name).isNotEmpty())
        secureFileSystem.deleteDir()
        Assert.assertTrue(secureFileSystem.read(name).isEmpty())
    }
}
