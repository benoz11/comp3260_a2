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
 *	'Decrypter.java'
 *  File Description:
 *		Reads the file given by the user - read the assumptions section for more specific info on the file requirements
 *		The system will run inverted AES on the ciphertext C under key K in order to retrieve the original plaintext P
 *		P will be output to the given filename, overwriting it if it exists
 *
 *	ASSUMPTIONS: 
 *  	input file is given in its full name, eg "input.txt" without quotes
 *  	input file is in the root of this project (COMP3260_A2_c3166457), or has its subfolder specified in the string eg "inputs/test.txt" without quotes
 *  	input file contains 2 lines, 128 characters long, containing only either 0's or 1's
 *  	input file line 1 is the ciphertext, line 2 is the key
 *  	output file will be placed in this root folder unless its subfolder is specified in the string
 *  
 *  NOTEs:
 *  	output file will be overwritten if it already exists
 */
package cryption;

import java.util.ArrayList;

import aes.AESHandler;
import aes.RoundHandler;
import helper.Converter;
import io.FileHandler;

public class Decrypter {

	public Decrypter() {
		init();
	}
	
	public void init() {
		FileHandler fh = new FileHandler();  //runs ih.init() which Handles input file prompt prompt, sets text/key in the filehandler (retrieve with get methods)
		

		System.out.println("Please enter the output file name");
		String outputFilename = fh.getFilename();
		
		String C = fh.getText();
		String K = fh.getKey();
		Converter converter = new Converter();
		RoundHandler rh = new RoundHandler(converter.binaryStringToIntTable(K));
		
		AESHandler aeshandler = new AESHandler(C,K,rh);
		
		String P = aeshandler.AESDecrypt(); //Decrypts C under K to get the binary string plaintext P
		
		//Create arraylist of strings representing each line to write to the file
		ArrayList<String> outputLines = new ArrayList<>();
		outputLines.add("DECRYPTION");
		outputLines.add("Ciphertext C: "+C);
		outputLines.add("Key K: "+K);
		outputLines.add("Plaintext P: "+P); //AES0 after all 10 rounds
		
		fh.writeToFile(outputLines,outputFilename); //write to file
		
		System.out.println("\nProcess complete! Results written to "+outputFilename);	
	}
}
