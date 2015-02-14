package edu.cedarville.cs.crypto;

public class TinyE {
	
    public static enum Mode { ECB, CBC, CTR };
    private final String DELTA = "9E3779B9";
    private final int DELTA_INT = 0x9e3779b9;

    public Integer[] encrypt(Integer[] plaintext, Integer[] key, Mode mode, Integer[] iv) {
        switch (mode) {
            case ECB:
                // Stuff
                break;
            case CBC:
                // more stuff
                break;
            case CTR:
                // more stuff
                break;
            default:
                // problemo
        }
        
        return null;
    }

    public Integer[] decrypt(Integer[] ciphertext, Integer[] key, Mode mode, Integer[] iv) {
        return null;
    }

    /**
     * The basic TEA encryption algorithm on one 64-bit block of data
     * @param plaintext an Integer[] - The 64-bit block to encrypt
     * @param key an Integer[] - The 128-bit key
     * @return the encrypted ciphertext
     * @throws TEAException if either parameter is not set properly
     */
    private Integer[] encryptBlock(Integer[] plaintext, Integer[] key) 
            throws TEAException {
        // check if the parameters are correctly filled
        if (!validText(plaintext)) {
            throw new TEAException("Plaintext incorrectly instantiated");
        }
        if (!validKey(key)) {
            throw new TEAException("Key incorrectly instantiated");
        }
        
        // Setup
        int l = plaintext[0];   // l is the left side of the text block
        int r = plaintext[1];   // r is the right side of the text block
        int sum = 0;
                
        // basic tea encrypt cycle
        for (int i=0; i < 32; i++) {
            sum += DELTA_INT;
            l += ((r<<4) + key[0]) ^ (r + sum) ^ ((r>>5) + key[1]);
            r += ((l<<4) + key[2]) ^ (l + sum) ^ ((l>>5) + key[3]);
        }

        Integer[] ciphertext = {l, r};
        return ciphertext;
    }
    
    /**
     * The basic TEA decryption algorithm on one 64-bit block of data
     * @param ciphertext an Integer[] - The 64-bit block to decrypt
     * @param key an Integer[] - The 128-bit key
     * @return the decrypted plaintext
     * @throws TEAException if either parameter is not set properly
     */
    private Integer[] decryptBlock(Integer[] ciphertext, Integer[] key) 
            throws TEAException {
        // check if the parameters are correctly filled
        if (!validText(ciphertext)) {
            throw new TEAException("Ciphertext incorrectly instantiated");
        }
        if (!validKey(key)) {
            throw new TEAException("Key incorrectly instantiated");
        }
        
        // Setup
        int l = ciphertext[0];   // l is the left side of the text block
        int r = ciphertext[1];   // r is the right side of the text block
        int sum = DELTA_INT << 5;
                
        // basic tea encrypt cycle
        for (int i=0; i < 32; i++) {
            r -= ((l<<4) + key[2]) ^ (l + sum) ^ ((l>>5) + key[3]);
            l -= ((r<<4) + key[0]) ^ (r + sum) ^ ((r>>5) + key[1]);
            sum -= DELTA_INT;
        }

        Integer[] plaintext = {l, r};
        return plaintext;
    }
    
    /**
     * Ensures that text is an Integer[] with 2 populated elements (64 bits)
     * @param text an array of Integers
     * @return true if array is filled, false if anything is null
     * @see Integer
     */
    private boolean validText(Integer[] text) {
        return arrayFilled(text, 2);
    }

    /**
     * Ensures that key is an Integer[] with 4 populated elements (128 bits)
     * @param key an array of Integers
     * @return true if key is filled, false if anything is null
     * @see Integer
     */
    private boolean validKey(Integer[] key) {
        return arrayFilled(key, 4);
    }

    /**
     * Checks if an array has all of the elements needed for encrypting or 
     * decrypting
     * @param arr Integer[] with key or text
     * @param size the number of elements that should be in the array
     * @return true if all elements are present, false otherwise
     */
    private boolean arrayFilled(Integer[] arr, int size) {
        // Check if arr is null or the wrong size
        if (arr == null || arr.length != size)
            return false;
        
        // Check if any elements of arr are null
        for (Integer i: arr) {
            if (i == null)
                return false;
        }
        
        return true;
    }
}
