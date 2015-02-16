package edu.cedarville.cs.crypto;

public class TinyE {
	
    public static enum Mode { ECB, CBC, CTR };
    private final int DELTA_INT = 0x9e3779b9;

    public Integer[] encrypt(Integer[] plaintext, Integer[] key, Mode mode, Integer[] iv) {
        
        Integer[] plainBlock = new Integer[2];
        Integer[] cipherBlock = new Integer[2];
        Integer[] ciphertext = new Integer[plaintext.length];
        
        switch (mode) {
            case ECB:
                for (int i = 0; i < plaintext.length; i+=2) {
                    plainBlock[0] = plaintext[i];
                    plainBlock[1] = plaintext[i+1];
                    try {
                        cipherBlock = this.encryptBlock(plainBlock, key);
                    }
                    catch (TEAException tiny) {
                        System.err.println(tiny.getMessage());
                        System.exit(1);
                    }
                    ciphertext[i] = cipherBlock[0];
                    ciphertext[i+1] = cipherBlock[1];
                }
                return ciphertext;
            case CBC:
                Integer[] xor = iv;
                
                for (int i = 0; i < plaintext.length; i+=2) {
                    plainBlock[0] = xor[0] ^ plaintext[i];
                    plainBlock[1] = xor[1] ^ plaintext[i+1];
                    try {
                        cipherBlock = this.encryptBlock(plainBlock, key);
                    }
                    catch (TEAException tiny) {
                        System.err.println(tiny.getMessage());
                        System.exit(1);
                    }
                    
                    xor[0] = cipherBlock[0];
                    xor[1] = cipherBlock[1];
                    
                    ciphertext[i] = cipherBlock[0];
                    ciphertext[i+1] = cipherBlock[1];
                }
                return ciphertext;
            case CTR: 
                long tempIV = ((((long)iv[0]) << 32) & 0xffffffff00000000l) |
                        ((long)(iv[1] & 0x00000000ffffffffl));
                
                for (int i = 0; i < plaintext.length; i+=2) {
                    try {
                        cipherBlock = this.encryptBlock(iv, key);
                    }
                    catch (TEAException tiny) {
                        System.err.println(tiny.getMessage());
                        System.exit(1);
                    }
                    
                    ciphertext[i] = plaintext[i] ^ cipherBlock[0];
                    ciphertext[i+1] = plaintext[i+1] ^ cipherBlock[1];
                    
                    tempIV++;
                    iv[0] = (int) (tempIV >> 32);
                    iv[1] = (int) tempIV;
                }
                return ciphertext;
        }
                
        return null;
    }

    public Integer[] decrypt(Integer[] ciphertext, Integer[] key, Mode mode, Integer[] iv) {
        
        Integer[] cipherBlock = new Integer[2];
        Integer[] plainBlock = new Integer[2];
        Integer[] plaintext = new Integer[ciphertext.length];
        
        switch (mode) {
            case ECB:
                for (int i = 0; i < ciphertext.length; i+=2) {
                    cipherBlock[0] = ciphertext[i];
                    cipherBlock[1] = ciphertext[i+1];
                    try {
                        plainBlock = this.decryptBlock(cipherBlock, key);
                    }
                    catch (TEAException tiny) {
                        System.err.println(tiny.getMessage());
                        System.exit(1);
                    }
                    plaintext[i] = plainBlock[0];
                    plaintext[i+1] = plainBlock[1];
                }
                return plaintext;
            case CBC:
                Integer[] xor = iv;
                
                for (int i = 0; i < ciphertext.length; i+=2) {
                    cipherBlock[0] = ciphertext[i];
                    cipherBlock[1] = ciphertext[i+1];
                    try {
                        plainBlock = this.decryptBlock(cipherBlock, key);
                    }
                    catch (TEAException tiny) {
                        System.err.println(tiny.getMessage());
                        System.exit(1);
                    }
                    
                    plaintext[i] = xor[0] ^ plainBlock[0];
                    plaintext[i+1] = xor[1] ^ plainBlock[1];
                    
                    xor[0] = ciphertext[i];
                    xor[1] = ciphertext[i+1];
                }
                return plaintext;
            case CTR:
                long tempIV = ((((long)iv[0]) << 32) & 0xffffffff00000000l) |
                        ((long)(iv[1] & 0x00000000ffffffffl));
                
                for (int i = 0; i < ciphertext.length; i+=2) {
                    try {
                        plainBlock = this.encryptBlock(iv, key);
                    }
                    catch (TEAException tiny) {
                        System.err.println(tiny.getMessage());
                        System.exit(1);
                    }
                    
                    plaintext[i] = ciphertext[i] ^ plainBlock[0];
                    plaintext[i+1] = ciphertext[i+1] ^ plainBlock[1];
                    
                    tempIV++;
                    long l = tempIV >> 32;
                    iv[0] = (int) (tempIV >> 32);
                    iv[1] = (int) tempIV;
                }
                return plaintext;
        }
        
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