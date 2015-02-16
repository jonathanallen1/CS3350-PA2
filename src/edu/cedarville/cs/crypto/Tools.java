/**
 * Implementation of encryption and decryption algorithms for TEA
 * 
 * @author Jonathan Allen and Jacob Secor
 * File: Tools.java
 * Date: 2/16/15
 * 
 * Summary of Modifications:
 * 
 * Description: This file, along with all the files in this package, are 
 * designed to implement the Tiny Encryption Algorithm for CS3350 Programming
 * Activity 2. This file provides the tools for converting hex strings and
 * binary strings to and from an Integer[]. The file was originally provided by 
 * Professor Hamman and contained only the empty stubs for the public methods.
 */

package edu.cedarville.cs.crypto;

public class Tools {
    // 8-bit ASCII value of tapping the spacebar
    private final static byte SPACE = 0b00100000;

    /**
     * Converts a byte array that represents a string into an Integer array
     * @param byteArr the byte array to convert
     * @return Integer[] with equivalent bit values to byteArr
     */
    public static Integer[] convertFromBytesToInts(byte[] byteArr) {
        // Append pad of spaces if byteArr's size isn't divisible by 64 bits
        int offset = byteArr.length % 8;
        byte[] pad;
        if (offset != 0) {
            pad = new byte[byteArr.length + (8 - offset)];
        }
        else {
            pad = new byte[byteArr.length];
        }

        // Copy the value over into the larger array and add padding
        System.arraycopy(byteArr, 0, pad, 0, byteArr.length);
        for (int i = byteArr.length; i < pad.length; i++) {
            pad[i] = SPACE;
        }

        // Each byte is 8 bits, so 4 chars is 32 bits (1 int)
        Integer[] toReturn = new Integer[pad.length/4];

        // Convert each 32 bit block in the byte array to an int
        for (int i = 0; i < toReturn.length; i++) {
            toReturn[i] = ((pad[(i*4)]     << 24) & 0xff000000) 
                        | ((pad[(i*4) + 1] << 16) & 0x00ff0000)
                        | ((pad[(i*4) + 2] <<  8) & 0x0000ff00)
                        | (pad[(i*4) + 3]         & 0x000000ff);
        }
        return toReturn;
    }

    /**
     * Convert a string of hex values to an Integer[]
     * @param hexStr the hex string to convert
     * @return Integer[] with equivalent value as hexStr
     */
    public static Integer[] convertFromHexStringToInts(String hexStr) {
        // Append padding of 0's if hexStr's size isn't divisible by 64 bits
        int offset = hexStr.length() % 16;
        String padded = hexStr.toUpperCase();
        if (offset != 0) {
            for (int i = offset; i < 16; i++) {
                padded += "0";
            }
        }

        // Each hex char is 4 bits, so 8 chars is 32 bits (1 int)
        Integer[] toReturn = new Integer[(padded.length())/8];

        // Convert each 32 bit block in the hex string to an int
        for (int i = 0; i < toReturn.length; i++) {
            // Need to use a different substr method for the last case
            if (i == toReturn.length-1) {
                toReturn[i] = Integer.parseUnsignedInt(
                        padded.substring(i*8), 16);                    
            }
            else {
                toReturn[i] = Integer.parseUnsignedInt(
                        padded.substring(i*8, (i+1)*8), 16);
            }
        }
        return toReturn;
    }

    /**
     * Convert an Integer[] to a byte[] with the same bit value
     * @param ints Integer[] to convert
     * @return byte[] with equivalent bit value of parameter
     */
    public static byte[] convertFromIntsToBytes(Integer[] ints) {
        // Each 32-bit int corresponds to 4 8-bit byte value
        byte[] toReturn = new byte[ints.length*4];
        for (int i = 0; i < ints.length; i++) {
            toReturn[(4*i) + 0] = (byte) ((int) ints[i] >> 24);
            toReturn[(4*i) + 1] = (byte) ((int) ints[i] >> 16);
            toReturn[(4*i) + 2] = (byte) ((int) ints[i] >>  8);
            toReturn[(4*i) + 3] = (byte) ((int) ints[i]);
        }

        return toReturn;
    }

    /**
     * Convert Integer[] to string of hex characters
     * @param ints Integer[] to convert
     * @return String representation of the Integer[]'s hex value
     */
    public static String convertFromIntsToHexString(Integer[] ints) {
        String s = "";
        // Need to do all 8 hex values separately so leading 0s aren't lost
        // Each 32-bit int equals 8 4-bit hex values
        for (Integer i : ints) {
            s += Integer.toString((i >> 28) & 0x0000000f, 16) 
               + Integer.toString((i >> 24) & 0x0000000f, 16)
               + Integer.toString((i >> 20) & 0x0000000f, 16)
               + Integer.toString((i >> 16) & 0x0000000f, 16)
               + Integer.toString((i >> 12) & 0x0000000f, 16)
               + Integer.toString((i >>  8) & 0x0000000f, 16)
               + Integer.toString((i >>  4) & 0x0000000f, 16)
               + Integer.toString((i) & 0x0000000f, 16);
        }
        return s;
    }
}