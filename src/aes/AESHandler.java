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
 *	'AESHandler.java'
 *	File Description:
 *		Handles the AES Encryption/Decryption
 *		AES0 AES1 ... AES4 are as described in the assignment specifications
 *		
 *	Code References:
 *		ref 1: Convert to string of bits - src: https://stackoverflow.com/a/12310078/5536102
 */
package aes;

public class AESHandler {
	String input;
	String key;
	int[][] intTable;
	
	public AESHandler(String input, String key) {
		this.input = input;
		this.key=key;
		intTable = binaryStringTointTable(input);
		
		//DEBUG
		/*
		System.out.println("input: "+input+"\n");
		RoundHandler rh = new RoundHandler();
		int[][] boxTable = rh.SubBytes(intTable);
		
		for (int i = 0; i < 4; i++) {
			String line = "";
			for (int j = 0; j < 4; j++) {
				line += Integer.toHexString(intTable[i][j]) + " ";
			}
			System.out.println(line);
		}
		System.out.println("\n-------------------\n");
		for (int i = 0; i < 4; i++) {
			String line = "";
			for (int j = 0; j < 4; j++) {
				line += Integer.toHexString(boxTable[i][j]) + " ";
			}
			System.out.println(line);
		}*/
		
	}
	
	public int[][] binaryStringTointTable(String input) {
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
	
	public String intTableToBinaryString(int[][] input) {
		String output = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output += String.format("%8s", Integer.toBinaryString(input[j][i] & 0xFF)).replace(' ','0'); //convert to binary string (from ref 1)
			}
		}
		return output;
	}
	

	/*
	 * AES
	 * The 5 variants of AES implementation described in the assignment specs
	 */
	
	public String AES0() {
		/*
		 * The standard AES, 9 rounds of sub shift mix round then a final round of sub shift round
		 */
		int[][] output = intTable;
		RoundHandler rh = new RoundHandler();
		
		//initial round
		output = rh.AddRoundKey(output);
		
		//loop 9 times
		for (int i = 0; i < 9; i++) {
			output = rh.SubBytes(output);
			output = rh.ShiftRows(output);
			output = rh.MixColumns(output);
			output = rh.AddRoundKey(output);
		}
		
		//final run through
		output = rh.SubBytes(output);
		output = rh.ShiftRows(output);
		output = rh.AddRoundKey(output);
		
		//return as string
		return intTableToBinaryString(output);
	}
	public String AES1() {
		int[][] output = intTable;
		
		//return as string
		return intTableToBinaryString(output);
	}
	public String AES2() {
		int[][] output = intTable;
		
		//return as string
		return intTableToBinaryString(output);
	}
	public String AES3() {
		int[][] output = intTable;
		
		//return as string
		return intTableToBinaryString(output);
	}
	public String AES4() {
		int[][] output = intTable;
		
		//return as string
		return intTableToBinaryString(output);
	}
}
