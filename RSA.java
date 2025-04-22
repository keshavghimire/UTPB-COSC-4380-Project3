import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * <h1>RSA</h1>
 * <p>This class implements a basic form of the RSA asymmetric encryption and digital signing system.</p>
 */
public class RSA {
    public BigInteger p;
    public BigInteger q;
    public BigInteger phi;
    public BigInteger d;
    private BigInteger n;
    private BigInteger e;

    public RSA(int bits) {
        p = Crypto.getPrime(bits, bits + 64, 10);
        q = Crypto.getPrime(bits, bits + 64, 10);
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("65537");
        d = Crypto.modularInverse(e, phi);
    }

    public BigInteger[] getPubKey() {
        return new BigInteger[]{e, n};
    }

    /**
     * Encrypts a message with the recipient's public key
     */
    public String encrypt(String message, BigInteger[] pubKey) {
        try {
            byte[] messageBytes = message.getBytes("UTF-8");
            
            // For simplicity, we'll just use the hash of the message if it's too large
            if (new BigInteger(1, messageBytes).compareTo(pubKey[1]) >= 0) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                messageBytes = md.digest(messageBytes);
            }
            
            BigInteger m = new BigInteger(1, messageBytes);
            BigInteger c = m.modPow(pubKey[0], pubKey[1]);
            return Base64.getEncoder().encodeToString(c.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypts a message with this instance's private key
     */
    public String decrypt(String ciphertext) {
        try {
            if (ciphertext == null) {
                return "[Decryption error: null ciphertext]";
            }
            
            byte[] bytes = Base64.getDecoder().decode(ciphertext);
            BigInteger c = new BigInteger(1, bytes);
            BigInteger m = c.modPow(d, n);
            return new String(m.toByteArray(), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            return "[Decryption error: " + e.getMessage() + "]";
        }
    }

    /**
     * Sign a message with this instance's private key
     */
    public String sign(String message) {
        try {
            // Hash the message to ensure it fits within the RSA key size
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = md.digest(message.getBytes("UTF-8"));
            
            // Sign the hash
            BigInteger m = new BigInteger(1, messageHash);
            BigInteger s = m.modPow(d, n);
            return Base64.getEncoder().encodeToString(s.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Verify a message signature using the signer's public key
     */
    public boolean verify(String message, String signature, BigInteger[] pubKey) {
        try {
            if (signature == null) {
                System.out.println("[Verification error: null signature]");
                return false;
            }
            
            // Decode signature
            byte[] sigBytes = Base64.getDecoder().decode(signature);
            BigInteger s = new BigInteger(1, sigBytes);
            
            // Recover hash from signature
            BigInteger m = s.modPow(pubKey[0], pubKey[1]);
            byte[] recoveredHash = m.toByteArray();
            
            // Eliminate possible leading zero from BigInteger conversion
            if (recoveredHash.length == 33 && recoveredHash[0] == 0) {
                byte[] tmp = new byte[32];
                System.arraycopy(recoveredHash, 1, tmp, 0, 32);
                recoveredHash = tmp;
            }
            
            // Hash original message
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = md.digest(message.getBytes("UTF-8"));
            
            // Compare hashes
            if (recoveredHash.length != messageHash.length) {
                return false;
            }
            
            for (int i = 0; i < messageHash.length; i++) {
                if (messageHash[i] != recoveredHash[i]) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            System.out.println("[Verification error: " + e.getMessage() + "]");
            return false;
        }
    }

    public static void main(String[] args) {
        RSA a = new RSA(512);
        BigInteger[] aPub = a.getPubKey();
        System.out.printf("p = %s%np = %s%nn = %s%nphi = %s%ne = %s%nd = %s%n%n", a.p, a.q, aPub[1], a.phi, aPub[0], a.d);

        RSA b = new RSA(512);
        BigInteger[] bPub = b.getPubKey();
        System.out.printf("p = %s%np = %s%nn = %s%nphi = %s%ne = %s%nd = %s%n%n", b.p, b.q, bPub[1], b.phi, bPub[0], b.d);

        // A sends a message to B
        String message1 = "Hello B!";
        System.out.printf("msg: %s%n", message1);
        
        // A signs the message
        String signature1 = a.sign(message1);
        System.out.printf("Signed by A (signature): %s%n", signature1);
        
        // A encrypts the message with B's public key
        String encryptedMessage1 = b.encrypt(message1, bPub);
        System.out.printf("Encrypted message sent to B: %s%n", encryptedMessage1);
        
        // B decrypts the message using B's private key
        String decryptedMessage1 = b.decrypt(encryptedMessage1);
        System.out.printf("Decrypted message: %s%n", decryptedMessage1);
        
        // A sends the signature separately (unencrypted)
        System.out.printf("Signature sent to B: %s%n", signature1);
        
        // B verifies the signature using A's public key
        boolean isValid1 = a.verify(decryptedMessage1, signature1, aPub);
        System.out.printf("Message authenticated by B: %s%n", isValid1);

        // B sends a message to A
        String message2 = "Hello A!";
        System.out.printf("msg: %s%n", message2);
        
        // B signs the message
        String signature2 = b.sign(message2);
        System.out.printf("Signed by B (signature): %s%n", signature2);
        
        // B encrypts the message with A's public key
        String encryptedMessage2 = a.encrypt(message2, aPub);
        System.out.printf("Encrypted message sent to A: %s%n", encryptedMessage2);
        
        // A decrypts the message using A's private key
        String decryptedMessage2 = a.decrypt(encryptedMessage2);
        System.out.printf("Decrypted message: %s%n", decryptedMessage2);
        
        // B sends the signature separately (unencrypted)
        System.out.printf("Signature sent to A: %s%n", signature2);
        
        // A verifies the signature using B's public key
        boolean isValid2 = b.verify(decryptedMessage2, signature2, bPub);
        System.out.printf("Message authenticated by A: %s%n", isValid2);
    }
}