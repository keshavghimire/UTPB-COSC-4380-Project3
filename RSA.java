import java.math.BigInteger;

/**
 * <h1>RSA</h1>
 * <p>This class implements a basic form of the RSA asymmetric encryption and digital signing system.</p>
 */
public class RSA {

    /**
     * <h3>p</h3>
     * <p>One of the two primes used to generate n</p>
     * <p><b>Do not leave this public</b></p>
     */
    public BigInteger p;
    // TODO

    /**
     * <h3>q</h3>
     * <p>One of the two primes used to generate n</p>
     * <p><b>Do not leave this public</b></p>
     */
    public BigInteger q;
    // TODO

    /**
     * <h3>phi</h3>
     * <p>The result of (p-1)(q-1)</p>
     * <p><b>Do not leave this public</b></p>
     */
    public BigInteger phi;
    // TODO

    /**
     * <h3>n</h3>
     * <p>The result of p*q</p>
     */
    private BigInteger n;

    /**
     * <h3>e</h3>
     * <p>Any number which is co-prime with n and one of two values (along with n) which make up the public key.</p>
     */
    private BigInteger e;

    /**
     * <h3>d</h3>
     * <p>The modular inverse of e and one of two values (along with n) which make up the private key.</p>
     * <p><b>Do not leave this public</b></p>
     */
    public BigInteger d;
    // TODO

    /**
     * <h3>RSA Constructor</h3>
     * <p>The constructor for the RSA class.</p>
     * <p>Accepts an int value indicating the desired bit width of the p and q parameters.</p>
     * <p>Generates random p and q, then from those derives n and phi</p>
     * @param bits The number of bits (bit width) desired for the p and q values.
     */
    public RSA(int bits) {
        // TODO
    }

    /**
     * <h3>getPubKey</h3>
     * <p>A simple getter method for the public key.</p>
     * @return An array of BigInteger containing e and n.
     */
    public BigInteger[] getPubKey() {
        return new BigInteger[] {e, n};
    }

    /**
     * <h3>encrypt</h3>
     * <p>Accepts a message String and a public key and returns the encrypted message.</p>
     * @param message A String containing a message (signed or in plaintext)
     * @param pubKey An array of BigInteger containing a public key [e, n].
     * @return The result of encrypting the message using the given public key.
     */
    public String encrypt(String message, BigInteger[] pubKey) {
        // TODO
        return null;
    }

    /**
     * <h3>decrypt</h3>
     * <p>Accepts a ciphertext and uses the private key stored in the member variables to decrypt.</p>
     * @param ciphertext A String containing an encryptedd message.
     * @return The result of decrypting the message using the private key [d, n].
     */
    public String decrypt(String ciphertext) {
        // TODO
        return null;
    }

    /**
     * <h3>sign</h3>
     * <p>Accepts a message String and cryptographically signs the message using the private key stored in the member variables [d, n].</p>
     * @param message A String containing a message to be signed.
     * @return The result of encrypting the message using the private key [d, n].
     */
    public String sign(String message) {
        // TODO
        return null;
    }

    /**
     * <h3>authenticate</h3>
     * <p>Accepts a signed (encrypted) message and a public key and uses the given public key to decrypt the message.</p>
     * @param message A String containing a signed message.
     * @param pubKey An array of BigInteger containing a public key [e, n].
     * @return The result of decrypting the message using the given public key.
     */
    public String authenticate(String message, BigInteger[] pubKey) {
        // TODO
        return null;
    }

    /**
     * <h3>main</h3>
     * <p><b>For testing purposes only.</b></p>
     * <p>Final submission should be a <b>safe</b> class implementation.</p>
     */
    public static void main(String[] args) {
        RSA a = new RSA(4096);
        BigInteger[] aPub = a.getPubKey();
        System.out.printf("p = %s%nq = %s%nn = %s%nphi = %s%ne = %s%nd = %s%n%n", a.p, a.q, aPub[1], a.phi, aPub[0], a.d);
        RSA b = new RSA(4096);
        BigInteger[] bPub = b.getPubKey();
        System.out.printf("p = %s%nq = %s%nn = %s%nphi = %s%ne = %s%nd = %s%n%n", b.p, b.q, bPub[1], b.phi, bPub[0], b.d);

        String message1 = "";
        System.out.printf("msg: %s%n", message1);
        String signed1 = a.sign(message1);
        System.out.printf("Signed by A ({msg}privA): %s%n", signed1);
        String cipher1 = a.encrypt(signed1, bPub);
        System.out.printf("Sent to B ({{msg}privA}pubB): %s%n", cipher1);

        String auth1 = b.decrypt(cipher1);
        System.out.printf("Received by B ({msg}privA): %s%n", auth1);
        String plain1 = b.authenticate(auth1, aPub);
        System.out.printf("Authenticated by B: %s%n", plain1);

        String message2 = "";
        System.out.printf("msg: %s%n", message2);
        String cipher2 = b.encrypt(message2, aPub);
        System.out.printf("Sending to A ({msg}pubA): %s%n", cipher2);
        String signed2 = b.sign(cipher2);
        System.out.printf("Signed by B ({{msg}pubA}privB): %s%n", signed2);

        String auth2 = a.authenticate(signed2, bPub);
        System.out.printf("Authenticated by A ({msg}pubA): %s%n", auth2);
        String plain2 = a.decrypt(auth2);
        System.out.printf("Received by A: %s%n", plain2);
    }
}
