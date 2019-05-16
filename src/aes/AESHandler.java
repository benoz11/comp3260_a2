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

import helper.Converter;

public class AESHandler {
	String input;
	String key;
	RoundHandler rh;
	Converter converter;
	int[][] intTable;
	int[][] keyTable;
	
	public AESHandler(String input, String key, RoundHandler rh) {
		this.input = input;
		this.key=key;
		converter = new Converter();
		intTable = converter.binaryStringToIntTable(input);
		keyTable = converter.binaryStringToIntTable(key);
		this.rh = rh;
		converter = new Converter();
		//rh = new RoundHandler(keyTable);
		
		//debugTest();//DEBUG
	}

	/*
	 * AES
	 * The 5 variants of AES implementation described in the assignment specs
	 * As well as a decryption method
	 */
	
	public String[] AES0() {
		/*
		 * The standard AES,initial addRound key --- then 9 rounds of sub, shift, mix --- then a final round of sub,shift
		 * returns a string array length 11 with each value being the output plaintext string after each step (0-10)
		 */
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		
		outputArray[0] = converter.intTableToBinaryString(intTable); //initial P as table
		
		//Copy table over
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j];
			}
		}
		
		//initial round
		output = rh.addRoundKey(output, 0);
		
		//loop 9 times
		for (int i = 0; i < 9; i++) {
			output = rh.subBytes(output);
			output = rh.shiftRows(output);
			output = rh.mixColumns(output);
			output = rh.addRoundKey(output, i+1); //round 1-9
			
			outputArray[i+1] = converter.intTableToBinaryString(output);
			
		}
		
		//final run through
		output = rh.subBytes(output);
		output = rh.shiftRows(output);
		output = rh.addRoundKey(output, 10); //round 10
		
		outputArray[10] = converter.intTableToBinaryString(output);
		
		//return as string
		return outputArray;
	}
	
	
	public String[] AES1() {
		/*
		 * AES0 without subBytes step
		 */
		
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		
		outputArray[0] = converter.intTableToBinaryString(intTable); //initial
		
		//Copy table over
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j];
			}
		}
		
		//initial round
		output = rh.addRoundKey(output, 0);
		
		//loop 9 times -- NO SUBSTITUTE BYTES STEP
		for (int i = 0; i < 9; i++) {
			output = rh.shiftRows(output);
			output = rh.mixColumns(output);
			output = rh.addRoundKey(output,i+1);
			
			outputArray[i+1] = converter.intTableToBinaryString(output);
		}
		
		//final run through -- NO SUBSTITUTE BYTES STEP
		output = rh.shiftRows(output);
		output = rh.addRoundKey(output,10);
		
		outputArray[10] = converter.intTableToBinaryString(output);
		
		return outputArray;
	}
	
	
	public String[] AES2() {
		/*
		 * AES0 without ShiftRows step
		 */
		
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		
		outputArray[0] = converter.intTableToBinaryString(intTable); //initial
		
		//Copy array over
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j];
			}
		}
		
		//initial  round
		output = rh.addRoundKey(output, 0);
		
		//loop 9 times -- NO SHIFT ROWS STEP
		for (int i = 0; i < 9; i++) {
			output = rh.subBytes(output);
			output = rh.mixColumns(output);
			output = rh.addRoundKey(output,i+1);
			
			outputArray[i+1] = converter.intTableToBinaryString(output);
		}
		
		//final run through -- NO SHIFT ROWS STEP
		output = rh.subBytes(output);
		output = rh.addRoundKey(output,10);
		
		outputArray[10] = converter.intTableToBinaryString(output);
		
		return outputArray;
	}
	
	
	public String[] AES3() {
		/*
		 * AES0 without mixColumns step
		 */
		
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		
		outputArray[0] = converter.intTableToBinaryString(intTable); //initial
		
		//Copy table over
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j];
			}
		}
		
		//initial round
		output = rh.addRoundKey(output, 0);
		
		//loop 9 times -- NO MIX COLUMNS STEP
		for (int i = 0; i < 9; i++) {
			output = rh.subBytes(output);
			output = rh.shiftRows(output);
			output = rh.addRoundKey(output,i+1);
			
			outputArray[i+1] = converter.intTableToBinaryString(output);
		}
		
		//final run through
		output = rh.subBytes(output);
		output = rh.shiftRows(output);
		output = rh.addRoundKey(output,10);
		
		outputArray[10] = converter.intTableToBinaryString(output);
		
		return outputArray;
	}
	
	
	public String[] AES4() {
		/*
		 * AES0 without Add round key step
		 */
		
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		
		outputArray[0] = converter.intTableToBinaryString(intTable); //initial
		
		//Copy over
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j];
			}
		}
		
		//initial round
		output = rh.addRoundKey(output, 0);
		
		//loop 9 times -- NO ADD ROUND KEY STEP
		for (int i = 0; i < 9; i++) {
			output = rh.subBytes(output);
			output = rh.shiftRows(output);
			output = rh.mixColumns(output);
			
			outputArray[i+1] = converter.intTableToBinaryString(output);
		}
		
		//final run through -- NO ADD ROUND KEY STEP
		output = rh.subBytes(output);
		output = rh.shiftRows(output);
		
		outputArray[10] = converter.intTableToBinaryString(output);
		
		return outputArray;
	}
	
	public String AESDecrypt() {
		/*
		 * run the inverted methods, in reverse order on a ciphertext binary string to return a plaintext binary string
		 */
		
		int[][] output = new int[4][4];
		//Copy table over
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j];
			}
		}
		
		//first round
		output = rh.addRoundKey(output, 10);
		output = rh.shiftRows(output,true);
		output = rh.subBytes(output,true);
		
		//loop 9 times
		for (int i = 9; i > 0; i--) {
			output = rh.addRoundKey(output, i); //round keys 9 through to 1
			output = rh.mixColumns(output,true); //inverse
			output = rh.shiftRows(output,true); //inverse
			output = rh.subBytes(output,true); //inverse 
		}
		
		//final round
		output = rh.addRoundKey(output, 0);
		
		return converter.intTableToBinaryString(output);
	}
	
}
