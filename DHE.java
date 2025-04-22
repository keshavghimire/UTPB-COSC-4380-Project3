import java.math.BigInteger;

/**
 * <h1>DHE</h1>
 * <p>This class implements the Diffie-Hellman key exchange protocol to establish a shared secret between two parties.</p>
 */
public class DHE {
    private BigInteger p; // Prime modulus
    private BigInteger g; // Generator
    private BigInteger privateKey; // Private key (random)
    private BigInteger publicKey; // Public key (g^privateKey mod p)

    /**
     * Constructor that initializes DHE with a prime and generator.
     * @param bits Approximate bit length for the prime.
     */
    public DHE(int bits) {
        p = Crypto.getPrime(bits, bits + 64, 10);
        g = Crypto.getGenerator(bits, p);
        generateKeys();
    }

    /**
     * Constructor that uses a specific prime and generator.
     * @param p Prime modulus.
     * @param g Generator.
     */
    public DHE(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
        generateKeys();
    }

    /**
     * Generates private and public keys.
     */
    private void generateKeys() {
        privateKey = Crypto.getRandom(128, p.bitLength() - 1);
        publicKey = Crypto.fastMod(g, privateKey, p);
    }

    /**
     * Returns the public key.
     * @return Array containing [g, p, publicKey].
     */
    public BigInteger[] getPublicKey() {
        return new BigInteger[]{g, p, publicKey};
    }

    /**
     * Computes the shared secret using the other party's public key.
     * @param otherPublicKey The other party's public key.
     * @return The shared secret.
     */
    public BigInteger computeSharedSecret(BigInteger otherPublicKey) {
        if (otherPublicKey == null || otherPublicKey.compareTo(p) >= 0) {
            throw new IllegalArgumentException("Invalid public key");
        }
        return Crypto.fastMod(otherPublicKey, privateKey, p);
    }

    public static void main(String[] args) {
        // Party A
        DHE a = new DHE(512);
        BigInteger[] aPub = a.getPublicKey();
        System.out.printf("A's public key: g = %s, p = %s, A = %s%n", aPub[0], aPub[1], aPub[2]);

        // Party B
        DHE b = new DHE(aPub[1], aPub[0]); // Use same p and g
        BigInteger[] bPub = b.getPublicKey();
        System.out.printf("B's public key: g = %s, p = %s, B = %s%n", bPub[0], bPub[1], bPub[2]);

        // A computes shared secret
        BigInteger sharedSecretA = a.computeSharedSecret(bPub[2]);
        System.out.printf("Shared secret computed by A: %s%n", sharedSecretA);

        // B computes shared secret
        BigInteger sharedSecretB = b.computeSharedSecret(aPub[2]);
        System.out.printf("Shared secret computed by B: %s%n", sharedSecretB);

        // Verify shared secrets match
        boolean secretsMatch = sharedSecretA.equals(sharedSecretB);
        System.out.printf("Shared secrets match: %s%n", secretsMatch);
    }
}