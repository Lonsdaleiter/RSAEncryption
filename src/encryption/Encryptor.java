package encryption;

/**
 * An interface representing an Encryptor.
 *
 * Contains two unimplemented methods to encrypt and
 * decrypt String to/from another String.
 *
 * @author Lonsdaleiter
 * */
public interface Encryptor {

    byte[] encrypt(String message) throws EncryptionException; // encrypts a String and outputs a byte[]
    byte[][] encryptPieces(String message) throws EncryptionException; // encrypts a String's characters individually to a byte[][]
    String decrypt(byte[] message) throws EncryptionException; // decrypts a byte[] and outputs a String
    String decrypt(byte[][] message) throws EncryptionException; // decrypts a byte[][] and outputs a String

}
