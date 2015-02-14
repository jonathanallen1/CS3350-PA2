/**
 * Exception class for errors that may occur in the TEA Encryption process.
 * 
 * @author Jonathan Allen
 * File: TEAException.java
 * Date: 2/13/15
 * 
 * Description: This exception class covers any potential errors that may
 * occur in the process of encrypting or decrypting a message with the Tiny
 * Encryption Algorithm (TEA)
 * @see Exception
 */

package edu.cedarville.cs.crypto;

class TEAException extends Exception {

    public TEAException(String message) {
        super(message);
    }
    
}
