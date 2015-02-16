package edu.cedarville.cs.crypto;

public class Tools {
	private static byte SPACE = 0b00100000;
        
	public static Integer[] convertFromBytesToInts(byte[] bs) {
            // Add padding of spaces at end of string if it's size isn't divisible by 64 bits
            int offset = bs.length % 8;
            byte[] pad;
            if (offset != 0) {
                pad = new byte[bs.length + offset];
            }
            else {
                pad = new byte[bs.length];
            }
            
            // Copy the value over into the larger array and add padding
            System.arraycopy(bs, 0, pad, 0, bs.length);
            for (int i = bs.length; i < pad.length; i++) {
                pad[i] = SPACE;
            }
            
            // Each hex char is 4 bits, so 8 chars is 32 bits (1 int)
            Integer[] toReturn = new Integer[pad.length/4];
            
            // Convert each 32 bit block in the hex string to an int
            for (int i = 0; i < toReturn.length; i++) {
                toReturn[i] = ((pad[(i*4)    ] << 24) & 0xff000000) 
                            | ((pad[(i*4) + 1] << 16) & 0x00ff0000)
                            | ((pad[(i*4) + 2] <<  8) & 0x0000ff00)
                            | ((pad[(i*4) + 3]      ) & 0x000000ff);
            }
            return toReturn;
	}
	
	public static Integer[] convertFromHexStringToInts(String s) {
            // Add padding of 0's at end of string if it's size isn't divisible by 64 bits
            int offset = s.length() % 16;
            String padded = s.toUpperCase();
            if (offset != 0) {
                for (int i = offset; i < 16; i++) {
                    padded += "0";
                }
            }
            
            // Each hex char is 4 bits, so 8 chars is 32 bits (1 int)
            Integer[] toReturn = new Integer[(padded.length())/8];
            
            // Convert each 32 bit block in the hex string to an int
            for (int i = 0; i < toReturn.length; i++) {
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
	
	public static byte[] convertFromIntsToBytes(Integer[] ints) {
            byte[] toReturn = new byte[ints.length*4];
            
            for (int i = 0; i < ints.length; i++) {
                toReturn[(4*i) + 0] = (byte) ((int) ints[i] >> 24);
                toReturn[(4*i) + 1] = (byte) ((int) ints[i] >> 16);
                toReturn[(4*i) + 2] = (byte) ((int) ints[i] >>  8);
                toReturn[(4*i) + 3] = (byte) ((int) ints[i]);
            }
            
            return toReturn;
	}
	
	public static String convertFromIntsToHexString(Integer[] ints) {
            String s = "";
            // Need to do all 8 hex values separately so leading 0s aren't lost
            for (Integer i : ints) {
                s += Integer.toUnsignedString((i >> 28) & 0x0000000f, 16) 
                   + Integer.toUnsignedString((i >> 24) & 0x0000000f, 16)
                   + Integer.toUnsignedString((i >> 20) & 0x0000000f, 16)
                   + Integer.toUnsignedString((i >> 16) & 0x0000000f, 16)
                   + Integer.toUnsignedString((i >> 12) & 0x0000000f, 16)
                   + Integer.toUnsignedString((i >>  8) & 0x0000000f, 16)
                   + Integer.toUnsignedString((i >>  4) & 0x0000000f, 16)
                   + Integer.toUnsignedString((i) & 0x0000000f, 16);
            }
            return s;
	}
}