import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Scanner;

/**
 * <h1>Crypto</h1>
 * <p>This class is a collection of methods for use in the other libraries contained in this project (DHE, RSA, and AES).</p>
 * <p>It uses relatively secure methods for generating large random values and tests for primality.</p>
 * <p>It provides mathematical functions for performing fast modular exponentiation and finding primitive root and modular inverse.</p>
 */
public class Crypto {

    public static final HashMap<Integer, Integer> RC = new HashMap<>();
    static {
        RC.put(1, 0x01);
        RC.put(2, 0x02);
        RC.put(3, 0x04);
        RC.put(4, 0x08);
        RC.put(5, 0x10);
        RC.put(6, 0x20);
        RC.put(7, 0x40);
        RC.put(8, 0x80);
        RC.put(9, 0x1B);
        RC.put(10, 0x36);
    }

    public static BigInteger fastMod(BigInteger g, BigInteger a, BigInteger p) {
        BigInteger result = BigInteger.ONE;
        BigInteger base = g.mod(p);
        while (a.compareTo(BigInteger.ZERO) > 0) {
            if (a.testBit(0)) {
                result = result.multiply(base).mod(p);
            }
            base = base.multiply(base).mod(p);
            a = a.shiftRight(1);
        }
        return result;
    }

    public static boolean isValidG(BigInteger g, BigInteger p) {
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        if (g.modPow(BigInteger.TWO, p).equals(BigInteger.ONE)) return false;
        if (g.modPow(q, p).equals(BigInteger.ONE)) return false;
        return true;
    }

    /**
     * Generates a valid generator for the given prime p.
     * @param bits Approximate bit length for generator (unused in optimized version).
     * @param p Prime modulus.
     * @return A valid generator g such that g is a primitive root modulo p.
     */
    public static BigInteger getGenerator(int bits, BigInteger p) {
        // Try small generators first (common in DHE)
        BigInteger[] smallGenerators = {
            BigInteger.valueOf(2), BigInteger.valueOf(3), BigInteger.valueOf(5), BigInteger.valueOf(7)
        };
        for (BigInteger g : smallGenerators) {
            if (g.compareTo(p) < 0 && isValidG(g, p)) {
                return g;
            }
        }
        // Fallback to random search with limited attempts
        int maxAttempts = 100;
        for (int i = 0; i < maxAttempts; i++) {
            BigInteger g = getRandom(2, p.bitLength() - 1);
            if (g.compareTo(p) < 0 && isValidG(g, p)) {
                return g;
            }
        }
        throw new ArithmeticException("No valid generator found for p = " + p);
    }

    public static BigInteger getRandom(int minBits, int maxBits) {
        BigInteger result = new BigInteger(maxBits, Rand.getRand());
        while (result.bitLength() <= minBits || result.equals(BigInteger.ZERO)) {
            result = new BigInteger(maxBits, Rand.getRand());
        }
        return result;
    }

    public static boolean checkPrime(BigInteger p, int numChecks) {
        // Trial Division
        try (Scanner scan = new Scanner(new File("primes.txt"))) {
            while (scan.hasNext()) {
                BigInteger b = new BigInteger(scan.nextLine());
                if (p.mod(b).equals(BigInteger.ZERO)) return false;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        // Fermat's Little Theorem
        BigInteger pm = p.subtract(BigInteger.ONE);
        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            if (!fastMod(a, pm, p).equals(BigInteger.ONE)) return false;
        }

        // Miller-Rabin
        BigInteger s = BigInteger.ZERO;
        BigInteger d = pm;
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            s = s.add(BigInteger.ONE);
            d = d.shiftRight(1);
        }

        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            BigInteger x = fastMod(a, d, p);
            if (x.equals(BigInteger.ONE) || x.equals(pm)) continue;

            boolean passed = false;
            for (BigInteger j = BigInteger.ONE; j.compareTo(s) < 0; j = j.add(BigInteger.ONE)) {
                x = x.multiply(x).mod(p);
                if (x.equals(pm)) {
                    passed = true;
                    break;
                }
            }

            if (!passed) return false;
        }

        return true;
    }

    public static BigInteger getPrime(int minBits, int maxBits, int numChecks) {
        BigInteger p = getRandom(minBits, maxBits);
        int attempts = 0;
        while (!checkPrime(p, numChecks)) {
            p = getRandom(minBits, maxBits);
            attempts++;
        }
        System.out.printf("Checked %d numbers for primality%n", attempts);
        return p;
    }

    public static BigInteger getSafePrime() {
        while (true) {
            BigInteger q = getPrime(2048, 3072, 10);
            BigInteger p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
            if (checkPrime(p, 10)) return p;
        }
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        return b.equals(BigInteger.ZERO) ? a : gcd(b, a.mod(b));
    }

    public static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        BigInteger[] vals = extendedGCD(b, a.mod(b));
        BigInteger gcd = vals[0];
        BigInteger x1 = vals[1];
        BigInteger y1 = vals[2];
        BigInteger x = y1;
        BigInteger y = x1.subtract(a.divide(b).multiply(y1));
        return new BigInteger[]{gcd, x, y};
    }

    public static BigInteger modularInverse(BigInteger e, BigInteger phi) {
        BigInteger[] result = extendedGCD(e, phi);
        BigInteger gcd = result[0];
        BigInteger x = result[1];
        if (!gcd.equals(BigInteger.ONE)) {
            throw new ArithmeticException("Inverse does not exist");
        }
        return x.mod(phi);
    }

    public static void main(String[] args) {
        // For testing
        BigInteger[] egcd = extendedGCD(new BigInteger("65537"), new BigInteger("3120"));
        System.out.println("GCD: " + egcd[0] + ", x: " + egcd[1] + ", y: " + egcd[2]);
    }
}