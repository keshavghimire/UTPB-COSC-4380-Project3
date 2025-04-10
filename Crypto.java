import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.Scanner;

/**
 * <h1>Crypto</h1>
 * <p>This class is a collection of methods for use in the other libraries contained in this project (DHE, RSA, and AES).</p>
 * <p>It uses relatively secure methods for generating large random values and tests for primality.</p>
 * <p>It provides mathematical functions for performing fast modular exponentiation and finding primitive root and modular inverse.</p>
 */
public class Crypto {

    /**
     * <h3>fastMod</h3>
     * <p>Implementation of the fast modular exponentiation algorithm using BigInteger</p>
     * @param g
     * @param a
     * @param p
     * @return The result of g^a mod p
     */
    public static BigInteger fastMod(BigInteger g, BigInteger a, BigInteger p) {
        int bitWidth = a.bitLength();
        BigInteger one = new BigInteger("1");
        BigInteger b = BigInteger.ZERO.add(a);
        boolean bits[] = new boolean[bitWidth];
        for (int i = 0; i < bitWidth; i++) {
            boolean bit = b.and(one).equals(one);
            bits[bitWidth-i-1] = bit;
            b.shiftRight(1);
        }

        BigInteger result =  new BigInteger("1");
        for (int i = 0; i < bitWidth; i++) {
            result.pow(2);
            result.mod(p);
            if (bits[i]) {
                result.multiply(g);
                result.mod(p);
            }
        }
        return result;
    }

    /**
     * <h3>isValidG</h3>
     * <p>Tests candidate generator values (primitive root mod p) for DHE.</p>
     * <p>In order to be a valid generator, g must satisfy the conditions g^2 mod p != 1 and g^q mod p != 1 for p = 2q+1.</p>
     * @param g
     * @param p
     * @return True if g is a valid primitive root mod p, false otherwise.
     */
    public static boolean isValidG(BigInteger g, BigInteger p) {
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        if (g.modPow(BigInteger.TWO, p).equals(BigInteger.ONE)) {
            return false;
        }
        if (g.modPow(q, p).equals(BigInteger.ONE)) {
            return false;
        }
        return true;
    }

    /**
     * <h3>getGenerator</h3>
     * <p>Accepts a target bit width and a prime modulus, and checks candidate generator values starting at a random initial value until it finds a valid primitive root mod p.</p>
     * @param bits
     * @param p
     * @return The first valid generator discovered.
     */
    public static BigInteger getGenerator(int bits, BigInteger p) {
        // TODO: Generate an initial g with the given bit width.
        for (BigInteger g = ; g.compareTo(p) < 0; g.add(BigInteger.ONE)) {
            if (isValidG(g, p)) {
                return g;
            }
        }
        return null;
    }

    /**
     * <h3>getRandom</h3>
     * <p>Securely generates a random BigInteger such that the value is only expressable with a number of bits in the range (minBits, maxBits)</p>
     * @param minBits
     * @param maxBits
     * @return A random BigInteger satisfying the requirements.
     */
    public static BigInteger getRandom(int minBits, int maxBits) {
        BigInteger result = new BigInteger(maxBits, Rand.getRand());
        while (result.bitLength() <= minBits) {
            result = new BigInteger(maxBits, Rand.getRand());
        }
        return result;
    }

    /**
     * <h3>checkPrime</h3>
     * <p>Checks a number for primality using three tests: trial division; Fermat's little theorem; and the Miller-Rabin test.</p>
     * @param p
     * @param numChecks How many iterations of Fermat's and M-R to perform before deciding that the number is likely prime.
     * @return True if the number passes all tests, false otherwise.
     */
    public static boolean checkPrime(BigInteger p, int numChecks) {
        // Trial Division
        boolean isPrime = true;
        try {
            Scanner scan = new Scanner(new File("primes.txt"));
            while(scan.hasNext()) {
                BigInteger b = new BigInteger(scan.nextLine());
                if (p.mod(b).equals(BigInteger.ZERO)) {
                    isPrime = false;
                    break;
                }
            }
            scan.close();
        } catch (FileNotFoundException fnfEx) {
            fnfEx.printStackTrace();
        }
        if (!isPrime) {
            return false;
        }

        // Fermat's Little Theorem
        BigInteger pm = p.subtract(BigInteger.ONE);
        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            if (!fastMod(a, pm, p).equals(BigInteger.ONE)) {
                return false;
            }
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
            for (BigInteger j = BigInteger.ZERO;
                 !j.equals(s);
                 j = j.add(BigInteger.ONE)) {
                x = x.pow(2);
                BigInteger y = x.mod(p);
                if (y.equals(BigInteger.ONE) && !x.equals(BigInteger.ONE) && !x.equals(pm)) {
                    return false;
                }
                x = y;
            }
            if (!x.equals(BigInteger.ONE)) {
                return false;
            }
        }

        return isPrime;
    }

    /**
     * <h3>getPrime</h3>
     * <p>Generates random numbers and checks them against checkPrime() until one passes the tests.</p>
     * @param minBits The minimum size (bit width) of the desired prime number.
     * @param maxBits The maximum size of the desired number.
     * @param numChecks The number of iterations of primality checking to perform.
     * @return The generated <i>likely-prime</i> number.
     */
    public static BigInteger getPrime(int minBits, int maxBits, int numChecks) {
        int i = 0;
        BigInteger p = getRandom(minBits, maxBits);
        while (!checkPrime(p, numChecks)) {
            i += 1;
            p = getRandom(minBits, maxBits);
        }
        System.out.printf("Checked %d numbers for primality%n", i);
        return p;
    }

    /**
     * <h3>getSafePrime</h3>
     * <p>Generates and checks prime numbers for use in DHE.</p>
     * <p>A "safe" prime has the form p = 2q+1 where q is a prime number, so we generate candidate values for q, check them for primality, then (for those which are likely prime) check the resulting p for primality.</p>
     * @return The first discovered safe prime which falls within the specified range.
     */
    public static BigInteger getSafePrime() {
        while(true) {
            BigInteger q = getPrime(2048, 3072, 10);
            //System.out.printf("%s is likely prime%n", q);
            BigInteger p = q;
            p = p.multiply(BigInteger.TWO);
            p = p.add(BigInteger.ONE);
            if (checkPrime(p, 10)) {
                return p;
            }
            //System.out.printf("Failed to find valid p for q = %s%n", q);
        }
    }

    /**
     * <h3>gcd</h3>
     * <p>An implementation of the Euclidean Algorithm for finding the gcd of two numbers a and b (where a > b).</p>
     * @param a
     * @param b
     * @return The result of gcd(a, b).
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return a;
        }
        return gcd(b, a.mod(b));
    }

    /**
     * <h3>extendedGCD</h3>
     * <p>An implementation of the extended Euclidean, which returns an array containing [gcd, i, j] where i and j are the coefficients which satisfy ix + jy = gcd(a,b).</p>
     * @param a
     * @param b
     * @return An array containing the values [gcd(a,b), i, j].
     */
    public static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }
        BigInteger[] values = extendedGCD(b, a.mod(b));
        BigInteger gcd = values[0];
        BigInteger x1 = values[1];
        BigInteger y1 = values[2];
        //BigInteger x = y1;x
        BigInteger y = x1.subtract(a.divide(b).multiply(y1));
        System.out.printf("gcd = %s, a = %s, b = %s%n", gcd, y1, y);
        return new BigInteger[]{gcd, y1, y};
    }

    /**
     * <h3>modularInverse</h3>
     * <p>Computes the modular inverse (private key) of an RSA public key given e and phi.</p>
     * @param e
     * @param phi
     * @return The modular inverse (private key) value.
     */
    public static BigInteger modularInverse(BigInteger e, BigInteger phi) {
        BigInteger[] result = extendedGCD(e, phi);
        BigInteger gcd = result[0];
        BigInteger x = result[1];
        if (!gcd.equals(BigInteger.ONE)) {
            throw new ArithmeticException("Inverse does not exist");
        }
        return x.mod(phi);
    }

    /**
     * <h3>main</h3>
     * <p>For testing purposes.</p>
     */
    public static void main(String[] args) {
        extendedGCD(new BigInteger("65537"), new BigInteger("3120"));
    }
}
