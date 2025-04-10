import java.util.HashMap;

public class AES {

    private int[] keySchedule;

    private static final HashMap<Integer, Integer> RC = new HashMap<>();
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

    public AES(String key) {
        keyExpansion(key);
    }

    public String encrypt(String plaintext, boolean cbcMode) {
        cipher(, true);
    }

    public String decrypt(String ciphertext, boolean cbcMode) {
        cipher(, false);
    }

    public String cipher(int[][] block, boolean encryptMode) {
        if (encryptMode) {
            addRoundKey(block, roundkey[0]);

            for (int round = 1; round < N; round++) {
                subBytes(block, encryptMode);
                shiftRows(block, encryptMode);
                mixColumns(block, encryptMode);
                addRoundKey(block, roundKey[round]);
            }

            subBytes(block, encryptMode);
            shiftRows(block, encryptMode);
            addRoundKey(block, roundKey[N]);
        } else {
            addRoundKey(block, roundKey[N]);
            shiftRows(block, encryptMode);
            subBytes(block, encryptMode);

            for (int round = 1; round < N; round++) {
                addRoundKey(block, roundKey[N - round - 1]);
                mixColumns(block, encryptMode);
                shiftRows(block, encryptMode);
                subBytes(block, encryptMode);
            }

            addRoundKey(block, roundkey[0]);
        }
    }

    private byte[][] getBlock(String text, int blockIdx) {

    }

    private void keyExpansion(int[] key) {

    }

    private int[] rotWord(int[] word) {
        int[] rot = new int[4];
        rot[0] = word[1];
        rot[1] = word[2];
        rot[2] = word[3];
        rot[3] = word[0];
        return rot;
    }

    private void subBytes(int[][] block, boolean mode) {
        for(int r = 0; r < 4; r++) {
            for(int c = 0; c < 4; c++) {
                block[r][c] = mode ? SBox.sbox(block[r][c]) : SBox.invSbox(block[r][c]);
            }
        }
    }

    private void shiftRows(int[][] block, boolean mode) {
        for (int r = 1; r < 4; r++) {
            int[] temp = new int[4];
            for (int c = 0; c < 4; c++) {
                temp[c] = mode ? block[r][(c+r)%4] : block[r][(c-r)%4];
            }
            block[r] = temp;
        }
    }

    private void mixColumns(int[][] block, boolean mode) {

    }

    private void addRoundKey(int[][] block, int[][] roundKey) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                block[r][c] = block[r][c] ^ roundKey[r][c];
            }
        }
    }

    public static void main(String[] args) {
        AES aes = new AES();
    }
}
