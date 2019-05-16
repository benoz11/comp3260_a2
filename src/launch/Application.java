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
 *
 *	'Application.java'
 *  File Description:
 *		The main file for the program. Takes a numerical selection from the user and offloads to the relevant section
 *
 */

package launch;

import java.util.Scanner;
import cryption.*;

public class Application {
	@SuppressWarnings({ "resource", "unused" }) //System.in scanner doesn't need to be closed, enc and dec are infact used, their constructors handle the work
	public static void main(String[] args) {
		//input selection scanner
		Scanner keypress = new Scanner(System.in);
		
		//Welcome and select Encryption/Decryption/Exit
		System.out.println("Welcome - Please enter a numerical value to select an option: ");
		System.out.println("1 - Encryption Program");
		System.out.println("2 - Decryption Program");
		System.out.println("Anything else - Exit");
		
		String input = keypress.next();
		if (input.equals("1")) {Encrypter enc = new Encrypter();} //offload to encrypter
		else if (input.equals("2")) {Decrypter dec = new Decrypter();} //offload to decrypter
		System.out.println("\nExiting program...");
	}
}
