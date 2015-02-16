/**
 * Implementation of encryption and decryption algorithms for TEA
 * 
 * @author Jonathan Allen and Jacob Secor
 * File: TinyE.java
 * Date: 2/16/15
 * 
 * Summary of Modifications:
 * 
 * Description: This file, along with all the files in this package, are 
 * designed to implement the Tiny Encryption Algorithm for CS3350 Programming
 * Activity 2. This file provides the actual encrypt and decrypt methods for
 * Tiny, as well as other supporting methods. The file was originally provided
 * by Professor Hamman and contained only the empty stubs for the public
 * methods.
 */

package edu.cedarville.cs.crypto;

public class TinyE {
	
    public static enum Mode { ECB, CBC, CTR };
    private final int DELTA_INT = 0x9e3779b9;

    /**
     * Encrypts an array of Integers using the given key, mode, and array.
     * @param plaintext length must be even, so that all 64 bit blocks are
     * present. This is verified in the conversions in Tools.java
     * @param key 64 bits (Integer[] of length 2)
     * @param mode ECB, CBC, or CTR - used for encrypting multiple blocks
     * @param iv used by CBC and CTR modes
     * @return Encrypted message Integer[] of same length as plaintext
     */
    public Integer[] encrypt(Integer[] plaintext, Integer[] key, Mode mode, 
            Integer[] iv) {
        // Make sure the parameters are properly provided
        checkParams(plaintext, key, mode, iv);   
        
        switch (mode) {
            case CBC:
                return encryptCBC(plaintext, key, iv);
            case CTR:
                return cryptCTR(plaintext, key, iv);
            case ECB:
            default:
                return encryptECB(plaintext, key);            
        }
    }

    /**
     * Decrypts an array of Integers using the given key, mode, and array.
     * @param ciphertext length must be even, so that all 64 bit blocks are
     * present. This is verified in the conversions in Tools.java
     * @param key 64 bits (Integer[] of length 2)
     * @param mode ECB, CBC, or CTR - used for decrypting multiple blocks
     * @param iv used by CBC and CTR modes
     * @return Decrypted message Integer[] of same length as ciphertext
     */
    public Integer[] decrypt(Integer[] ciphertext, Integer[] key, Mode mode, 
            Integer[] iv) {
        // Make sure the parameters are properly provided
        checkParams(ciphertext, key, mode, iv);        
               
        switch (mode) {
            case CBC:
                return decryptCBC(ciphertext, key, iv);
            case CTR:
                return cryptCTR(ciphertext, key, iv);
            case ECB:
            default:
                return decryptECB(ciphertext, key);
        }
    }
    
    /**
     * Encrypt a message with ECB mode
     * @param plaintext the plaintext Integer[]
     * @param key Integer[]
     * @return Integer[] of encrypted message
     */
    private Integer[] encryptECB(Integer[] plaintext, Integer[] key) {
        // Init variables
        Integer[] cipherBlock;
        Integer[] plainBlock = new Integer[2];
        Integer[] ciphertext = new Integer[plaintext.length];

        // Cycle through each 64-bit block (every 2 Integers)
        for (int i = 0; i < plaintext.length; i+=2) {
            plainBlock[0] = plaintext[i];
            plainBlock[1] = plaintext[i+1];

            // Encrypt block
            cipherBlock = this.encryptBlock(plainBlock, key);

            // Append to full encrypted message
            ciphertext[i] = cipherBlock[0];
            ciphertext[i+1] = cipherBlock[1];
        }
        return ciphertext;
    }
    
    /**
     * Encrypt a message with CBC mode
     * @param plaintext the plaintext Integer[]
     * @param key Integer[] 128-bit key
     * @param iv Integer[] 64-bit iv
     * @return Integer[] of encrypted message
     */
    private Integer[] encryptCBC(Integer[] plaintext, Integer[] key, 
            Integer[] iv) {
        // Init variables
        Integer[] cipherBlock;
        Integer[] plainBlock = new Integer[2];
        Integer[] ciphertext = new Integer[plaintext.length];
        Integer[] xor = iv;

        // Cycle through each 64-bit block (2 integers = 64 bits)
        for (int i = 0; i < plaintext.length; i+=2) {
            plainBlock[0] = xor[0] ^ plaintext[i];
            plainBlock[1] = xor[1] ^ plaintext[i+1];

            // Encrypt block
            cipherBlock = this.encryptBlock(plainBlock, key);
            
            // reset xor variable
            xor[0] = cipherBlock[0];
            xor[1] = cipherBlock[1];

            // copy value into final array
            ciphertext[i] = cipherBlock[0];
            ciphertext[i+1] = cipherBlock[1];
        }
        return ciphertext;
    }
    
    /**
     * Encrypt or decrypt a message encrypted with CTR mode
     * @param oldtext the encrypted or decrypted Integer[]
     * @param key Integer[] 128-bit key
     * @param iv Integer[] 64-bit iv
     * @return Integer[] of decrypted or encrypted message
     */
    private Integer[] cryptCTR(Integer[] oldtext, Integer[] key, 
            Integer[] iv) {
        // Init variables
        Integer[] newBlock;
        Integer[] newtext = new Integer[oldtext.length];

        // holds 64 bit interpretation of iv for incrementing
        long tempIV = ((((long)iv[0]) << 32) & 0xffffffff00000000l) |
                ((long)(iv[1] & 0x00000000ffffffffl));

        for (int i = 0; i < oldtext.length; i+=2) {
            // CTR works like a stream cipher
            newBlock = this.encryptBlock(iv, key);

            // XOR 64 bit blocks together
            newtext[i] = oldtext[i] ^ newBlock[0];
            newtext[i+1] = oldtext[i+1] ^ newBlock[1];

            // increment iv
            tempIV++;
            iv[0] = (int) (tempIV >> 32);
            iv[1] = (int) tempIV;
        }
        return newtext;
    }
    
    /**
     * Decrypt a message encrypted with ECB mode
     * @param ciphertext the encrypted Integer[]
     * @param key Integer[]
     * @return Integer[] of decrypted message
     */
    private Integer[] decryptECB(Integer[] ciphertext, Integer[] key) {
        // Init variables
        Integer[] cipherBlock = new Integer[2];
        Integer[] plainBlock;
        Integer[] plaintext = new Integer[ciphertext.length];

        // Cycle through each 64-bit block;
        for (int i = 0; i < ciphertext.length; i+=2) {
            cipherBlock[0] = ciphertext[i];
            cipherBlock[1] = ciphertext[i+1];

            // Decrypt this block
            plainBlock = this.decryptBlock(cipherBlock, key);
            
            // append to full plaintext message
            plaintext[i] = plainBlock[0];
            plaintext[i+1] = plainBlock[1];
        }
        return plaintext;
    }
    
    /**
     * Decrypt a message encrypted with CBC mode
     * @param ciphertext the encrypted Integer[]
     * @param key Integer[] 128-bit key
     * @param iv Integer[] 64-bit iv
     * @return Integer[] of decrypted message
     */
    private Integer[] decryptCBC(Integer[] ciphertext, Integer[] key, 
            Integer[] iv) {
        // Init variables
        Integer[] cipherBlock = new Integer[2];
        Integer[] plainBlock;
        Integer[] plaintext = new Integer[ciphertext.length];
        Integer[] xor = iv;

        // Iterate through each 64-bit block
        for (int i = 0; i < ciphertext.length; i+=2) {
            // get next 64 bit block
            cipherBlock[0] = ciphertext[i];
            cipherBlock[1] = ciphertext[i+1];

            // decrypt block
            plainBlock = this.decryptBlock(cipherBlock, key);

            // Perform xor operation
            plaintext[i] = xor[0] ^ plainBlock[0];
            plaintext[i+1] = xor[1] ^ plainBlock[1];

            // Setup xor variable for next cylcle
            xor[0] = ciphertext[i];
            xor[1] = ciphertext[i+1];
        }
        return plaintext;
    }

    /**
     * The basic TEA encryption algorithm on one 64-bit block of data
     * @param plaintext an Integer[] - The 64-bit block to encrypt
     * @param key an Integer[] - The 128-bit key
     * @return the encrypted ciphertext
     */
    private Integer[] encryptBlock(Integer[] plaintext, Integer[] key) {
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
     */
    private Integer[] decryptBlock(Integer[] ciphertext, Integer[] key) {
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
     * Verify that all parameters were correctly filled.
     * @param text Integer[] containing the long message to encode or decode
     * @param key 128 bit key
     * @param mode ECB, CBC, or CTR
     * @param iv 64 bit iv if present
     */
    private void checkParams(Integer[] text, Integer[] key, Mode mode, 
            Integer[] iv) {
        // Size must be a multiple of 64-bits (2 integers)
        if (text.length % 2 != 0) {
            System.err.println("Text is not a multple of 64 bits.");
            System.exit(1);
        }
        else if (!arrayFilled(text, text.length)) {
            System.err.println("Text is not correctly filled.");
            System.exit(1);
        }
        else if (!arrayFilled(key, 4)) {
            System.err.println("Key is not correctly filled.");
            System.exit(1);            
        }
        else if (mode == null) {
            System.err.println("Mode is null. Please assign it a value.");
            System.exit(1);
        }
        else if (mode != Mode.ECB) {
            if (!arrayFilled(iv, 2)) {
                System.err.println("iv is not correctly filled.");
                System.exit(1);
            }
        }
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