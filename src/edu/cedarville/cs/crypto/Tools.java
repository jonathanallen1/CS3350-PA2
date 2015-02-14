package edu.cedarville.cs.crypto;

import java.io.UnsupportedEncodingException;

public class Tools {
	
	public static Integer[] convertFromBytesToInts(byte[] bs) {
            Integer[] toReturn = new Integer[bs.length];
            toReturn[0] = (bs[0]<<24) & 0xff000000;
            toReturn[1] = (bs[1]<<16) & 0x00ff0000;
            toReturn[2] = (bs[2]<<8)  & 0x0000ff00;
            toReturn[3] = (bs[3]<<0)  & 0x000000ff;
            return toReturn;
	}
	
	public static Integer[] convertFromHexStringToInts(String s) throws UnsupportedEncodingException {
            Integer[] toReturn = new Integer[(s.length())/4];
            toReturn[0] = (s.getBytes(s.substring(0, 2))[0]<<24) & 0xff000000;
            toReturn[1] = (s.getBytes(s.substring(2, 4))[0]<<16) & 0x00ff0000;
            toReturn[2] = (s.getBytes(s.substring(4, 6))[0]<<8)  & 0x0000ff00;
            toReturn[3] = (s.getBytes(s.substring(6, 8))[0]<<0)  & 0x000000ff;
            return toReturn;
	}
	
	public static byte[] convertFromIntsToBytes(Integer[] ints) {
            byte[] toReturn = new byte[ints.length];
            toReturn[0] = ints[0].byteValue();
            toReturn[1] = ints[1].byteValue();
            toReturn[2] = ints[2].byteValue();
            toReturn[3] = ints[3].byteValue();
            return toReturn;
	}
	
	public static String convertFromIntsToHexString(Integer[] ints) {
            String s = "";
            s += Integer.toHexString(ints[0]);
            s += Integer.toHexString(ints[1]);
            s += Integer.toHexString(ints[2]);
            s += Integer.toHexString(ints[3]);
            return s;
	}

}
