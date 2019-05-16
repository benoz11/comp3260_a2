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
 *	'Converter.java'
 *  File Description:
 *		description here
 */
package helper;

public class Converter {

	public String intTableToBinaryString(int[][] input) {
		String output = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output += String.format("%8s", Integer.toBinaryString(input[j][i] & 0xFF)).replace(' ','0'); //convert to binary string (from ref 1)
			}
		}
		return output;
	}
	
	public int[][] binaryStringToIntTable(String input) {
		/*
		 * Assumes a 128bit string of 0's and 1's, no spaces
		 * splits into 8 bit chunks stored as hex values in an integer
		 * returns a 2d int array of hex values representing each int from the input
		 * NOTE: AES table goes top to bottom then left to right
		 * 		eg: first int is at 0,0    second int is at 1,0
		 */
		
		int[][] intTable = new int[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				String part = input.substring(i*32 + j*8, i*32 + j*8 + 8); //separate into 8 bit chunks
				intTable[j][i] = Integer.parseInt(part,2); //get string as int
			}
		}
		return intTable;
	}
}
