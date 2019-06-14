import com.virgilsecurity.ratchet.exception.KeyStorageException
import com.virgilsecurity.ratchet.keystorage.FileOneTimeKeysStorage
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.*

class FileOneTimeKeysStorageTest {

    val identity = UUID.randomUUID().toString()
    val path = createTempDir().toPath()
    private lateinit var keyStorage: FileOneTimeKeysStorage

    @BeforeAll
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
            assertEquals(KeyStorageException.ILLEGAL_STORAGE_STATE, e.errorCode)
        }
    }

    @Test
    fun start_stopInteraction() {
        this.keyStorage.startInteraction()
        this.keyStorage.startInteraction()
    }
}