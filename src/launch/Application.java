/**
 * 	Author: 	Benjamin McDonnell - c3166457 - University of Newcastle - 2019
 *  Project: 	COMP3260_A2_c3166457
 *  Git: 		https://github.com/benoz11/comp3260_a2.git
 *
 *  Project Description:
 *		COMP3260 Assignment 2 for University of Newcastle
 *     	Implementation of AES128 Encryption and Decryption, including analysis of the 'Avalanche effect'
 *  		caused by making small changes to the input or omitting parts of the AES process
 *     	Input is a 2 lined text file of the plaintext/ciphertext and the key, both as 128 bit binary
 *			in input file 'input.txt'
 *
 *	'Application.java'
 *  File Description:
 *		The main file for the program. Takes input, runs encryption, outputs results 
 *
 */

package launch;

import aes.AESHandler;
import io.FileHandler;

public class Application {
	public static void main(String[] args) {
		FileHandler ih = new FileHandler();  //run ih.init() which Handles prompt, sets text/key
		
		AESHandler aeshandler = new AESHandler(ih.getText(),ih.getKey());
		
		//run the encryption/decryption
		//output results
		
		System.out.println("Exiting program.");
	}
}
