import java.util.Arrays;
import java.util.Base64;

public class AES {
    private static final int BLOCK_SIZE = 4;
    private static final int N = 10; // AES-128 uses 10 rounds
    private int[][][] roundKey = new int[N + 1][BLOCK_SIZE][BLOCK_SIZE];

    public AES(String key) {
        int[] keyBytes = new int[16];
        byte[] raw = key.getBytes();
        for (int i = 0; i < 16; i++) {
            keyBytes[i] = raw[i] & 0xFF;
        }
        keyExpansion(keyBytes);
    }

    public String encrypt(String plaintext, boolean cbcMode) {
        int[][] block = textToBlock(plaintext);
        cipher(block, true);
        byte[] raw = blockToBytes(block);
        return Base64.getEncoder().encodeToString(raw); // return as printable Base64
    }

    public String decrypt(String ciphertext, boolean cbcMode) {
        byte[] raw = Base64.getDecoder().decode(ciphertext);
        int[][] block = bytesToBlock(raw);
        cipher(block, false);
        return blockToText(block);
    }

    public void cipher(int[][] block, boolean encryptMode) {
        if (encryptMode) {
            addRoundKey(block, roundKey[0]);
            for (int round = 1; round < N; round++) {
                subBytes(block, true);
                shiftRows(block, true);
                mixColumns(block, true);
                addRoundKey(block, roundKey[round]);
            }
            subBytes(block, true);
            shiftRows(block, true);
            addRoundKey(block, roundKey[N]);
        } else {
            addRoundKey(block, roundKey[N]);
            shiftRows(block, false);
            subBytes(block, false);
            for (int round = N - 1; round > 0; round--) {
                addRoundKey(block, roundKey[round]);
                mixColumns(block, false);
                shiftRows(block, false);
                subBytes(block, false);
            }
            addRoundKey(block, roundKey[0]);
        }
    }

    private int[][] textToBlock(String text) {
        int[][] block = new int[BLOCK_SIZE][BLOCK_SIZE];
        byte[] bytes = Arrays.copyOf(text.getBytes(), 16);
        for (int i = 0; i < 16; i++) {
            block[i % 4][i / 4] = bytes[i] & 0xFF;
        }
        return block;
    }

    private String blockToText(int[][] block) {
        byte[] result = new byte[16];
        for (int i = 0; i < 16; i++) {
            result[i] = (byte) block[i % 4][i / 4];
        }
        return new String(result);
    }

    private byte[] blockToBytes(int[][] block) {
        byte[] result = new byte[16];
        for (int i = 0; i < 16; i++) {
            result[i] = (byte) block[i % 4][i / 4];
        }
        return result;
    }

    private int[][] bytesToBlock(byte[] bytes) {
        int[][] block = new int[4][4];
        for (int i = 0; i < 16; i++) {
            block[i % 4][i / 4] = bytes[i] & 0xFF;
        }
        return block;
    }

    private void keyExpansion(int[] key) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                roundKey[0][j][i] = key[i * 4 + j];
            }
        }
        for (int round = 1; round <= N; round++) {
            for (int i = 0; i < 4; i++) {
                int[] word = new int[4];
                if (i == 0) {
                    for (int j = 0; j < 4; j++) {
                        word[j] = roundKey[round - 1][j][3];
                    }
                    word = rotWord(word);
                    for (int j = 0; j < 4; j++) {
                        word[j] = SBox.sbox(word[j]);
                    }
                    word[0] ^= Crypto.RC.get(round);
                } else {
                    for (int j = 0; j < 4; j++) {
                        word[j] = roundKey[round][j][i - 1];
                    }
                }
                for (int j = 0; j < 4; j++) {
                    roundKey[round][j][i] = roundKey[round - 1][j][i] ^ word[j];
                }
            }
        }
    }

    private int[] rotWord(int[] word) {
        return new int[]{word[1], word[2], word[3], word[0]};
    }

    private void subBytes(int[][] block, boolean mode) {
        for (int r = 0; r < BLOCK_SIZE; r++) {
            for (int c = 0; c < BLOCK_SIZE; c++) {
                block[r][c] = mode ? SBox.sbox(block[r][c]) : SBox.invSbox(block[r][c]);
            }
        }
    }

    private void shiftRows(int[][] block, boolean mode) {
        for (int r = 1; r < BLOCK_SIZE; r++) {
            int[] temp = new int[BLOCK_SIZE];
            for (int c = 0; c < BLOCK_SIZE; c++) {
                temp[c] = mode ? block[r][(c + r) % BLOCK_SIZE] : block[r][(c - r + BLOCK_SIZE) % BLOCK_SIZE];
            }
            block[r] = temp;
        }
    }

    private void mixColumns(int[][] block, boolean mode) {
        // Placeholder for mixColumns and invMixColumns logic
    }

    private void addRoundKey(int[][] block, int[][] roundKey) {
        for (int r = 0; r < BLOCK_SIZE; r++) {
            for (int c = 0; c < BLOCK_SIZE; c++) {
                block[r][c] ^= roundKey[r][c];
            }
        }
    }

    public static void main(String[] args) {
        AES aes = new AES("thisIsASecretKey");
        String plaintext = "Hello AES World!";
        String encrypted = aes.encrypt(plaintext, false);
        String decrypted = aes.decrypt(encrypted, false);

        System.out.println("Plaintext : " + plaintext);
        System.out.println("Encrypted : " + encrypted);
        System.out.println("Decrypted : " + decrypted);
    }
}