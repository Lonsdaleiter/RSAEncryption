package encryption;

import java.math.BigInteger;
import java.util.Random;

/**
 * An implementation of the Encryptor interface
 * with RSA.
 *
 * @author Lonsdaleiter
 * */
public class RSAEncryptor implements Encryptor {

    private boolean privatelyInstantiated; // whether or not the encryptor was privately instantiated

    private BigInteger n; // the multiple of p and q
    private BigInteger e; // a number relatively prime to phi

    private BigInteger phi; // phi of n; (p - 1) * (q - 1)
    private BigInteger p; // a prime number (ideally close to q)
    private BigInteger q; // a prime number (ideally close to p)

    private BigInteger d; // the multiplicative inverse of e mod phi

    private static final int BIT_LENGTH = 1024; // the highest bit length which e can have

    /**
     * Public instantiation of the RSA encryptor.
     * */
    public RSAEncryptor(BigInteger n, BigInteger e){
        privatelyInstantiated = false;

        this.n = n;

        Random r = new Random();
        if (e == null){
            e = BigInteger.probablePrime(BIT_LENGTH / 2, r);
            while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
                e = e.add(BigInteger.ONE);
        }

        this.e = e;
    }

    /**
     * Private instantiation of the RSA encryptor.
     * */
    public RSAEncryptor(BigInteger p, BigInteger q, BigInteger e){
        privatelyInstantiated = true;

        this.n = p.multiply(q);
        this.p = p;
        this.q = q;

        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        Random r = new Random();
        if (e == null){
            e = BigInteger.probablePrime(BIT_LENGTH / 2, r);
            while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
                e = e.add(BigInteger.ONE);
        }

        this.e = e;

        d = e.modInverse(phi);
    }

    // these constructors aren't that useful
//    public RSAEncryptor(Random random){
//        this(BigInteger.probablePrime(BIT_LENGTH, random),
//                BigInteger.probablePrime(BIT_LENGTH, random), null);
//    }
//
//    public RSAEncryptor(){
//        this(new Random());
//    }

    /**
     * Encrypts a String message to a byte[] by converting it to
     * a byte[], and raising all to the power of e mod n, the public
     * keys.
     * */
    @Override
    public byte[] encrypt(String message) throws EncryptionException {
        if (new BigInteger(message.getBytes()).compareTo(n) >= 0)
            throw new EncryptionException("Message too big for the prime factors.");
        return ((new BigInteger(message.getBytes())).modPow(e, n)).toByteArray();
    }

    /**
     * Encrypts a String m's characters individually to a byte[][] to
     * avoid issues with the message size by raising each char to the
     * power of e mod n.
     * */
    @Override
    public byte[][] encryptPieces(String message) throws EncryptionException {
        byte[][] rtme = new byte[message.length()][];
        for (int i = 0; i < message.length(); i++)
            rtme[i] = encrypt(message.substring(i, i + 1));
        return rtme;
    }

    /**
     * Decrypts a byte[] message to its original message by
     * raising it to the power of d mod n.
     * */
    @Override
    public String decrypt(byte[] message) throws EncryptionException {
        if (!privatelyInstantiated)
            throw new EncryptionException("A privately instantiated encryptor may not decrypt.");
        return new String(((new BigInteger(message)).modPow(d, n)).toByteArray());
    }

    @Override
    public String decrypt(byte[][] message) throws EncryptionException {
        String str = "";
        for (byte[] m : message)
            str += decrypt(m);
        return str;
    }

}
