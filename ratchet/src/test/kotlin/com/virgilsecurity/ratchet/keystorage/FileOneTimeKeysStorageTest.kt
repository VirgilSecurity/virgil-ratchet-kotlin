import com.virgilsecurity.ratchet.exception.KeyStorageException
import com.virgilsecurity.ratchet.keystorage.FileOneTimeKeysStorage
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.*

class FileOneTimeKeysStorageTest {

    val identity = UUID.randomUUID().toString()
    val path = createTempDir().toPath()
    private lateinit var keyStorage: FileOneTimeKeysStorage

    @Before
    fun setup() {
        val crypto = VirgilCrypto()
        this.keyStorage = FileOneTimeKeysStorage(identity, crypto, crypto.generateKeyPair(), path)
    }

    @Test
    fun startInteraction() {
        this.keyStorage.startInteraction()
    }

    @Test
    fun stopInteraction_noStart() {
        try {
            this.keyStorage.stopInteraction()
        } catch (e: KeyStorageException) {
            Assert.assertEquals(KeyStorageException.ILLEGAL_STORAGE_STATE, e.errorCode)
        }
    }

    @Test
    fun start_stopInteraction() {
        this.keyStorage.startInteraction()
        this.keyStorage.startInteraction()
    }
}