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
 *  File Description:
 *		Handles the AES Encryption/Decryption
 *		AES0 AES1 ... AES4 are as described in the assignment specifications
 *		
 *	Code References:
 *		ref 1: String of bits to byte - src: https://stackoverflow.com/a/12310176/5536102
 *		ref 2: Byte to string of bits - src: https://stackoverflow.com/a/12310078/5536102
 */
package aes;

public class AESHandler {
	String input;
	String key;
	byte[][] byteTable;
	
	public AESHandler(String input, String key) {
		this.input = input;
		this.key = key;
		byteTable = binaryStringToByteTable(input);
		
		//DEBUG - testing conversion methods
		//System.out.println("original input value: "+input);
		//System.out.println("value after converting to byteTable and then back to string: "+byteTableToBinaryString(byteTable));
	}
	
	/*
	 * Conversion functions
	 */
	public byte[][] binaryStringToByteTable(String input) {
		/*
		 * Assumes string is 128 bits of 0's and 1's, no spaces
		 * Splits it into 16 x 8bit chunks
		 * Returns a 2d Byte array in a 4x4 table format representing the string
		 * NOTE: AES table goes top to bottom - left to right on insertion
		 * 		eg: first byte is at 0,0  second byte is at 1,0
		 */
		byte[][] byteTable = new byte[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				String part = input.substring(i*32 + j*8, i*32 + j*8 + 8); //separate into 8 bit chunks
				byteTable[j][i] = (byte)(int)Integer.valueOf(part,2); //Get string as Integer base 2, convert to int, convert to byte (from ref 1)
			}
		}
		return byteTable;
	}
	
	public String byteTableToBinaryString(byte[][] byteTable) {
		/*
		 * Assumes a 4x4 2d byte array
		 * Outputs a 128bit string of 0's and 1's representing the 16 bytes given in the array
		 * NOTE: AES table goes top to bottom - left to right on insertion
		 *		eg: first byte is at 0,0  second byte is at 1,0
		 */
		String output = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output += String.format("%8s", Integer.toBinaryString(byteTable[j][i] & 0xFF)).replace(' ','0'); //byte to binary string (from ref 2)
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
		byte[][] output = byteTable;
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
		return byteTableToBinaryString(output);
	}
	public String AES1() {
		byte[][] output = byteTable;
		
		//return as string
		return byteTableToBinaryString(output);
	}
	public String AES2() {
		byte[][] output = byteTable;
		
		//return as string
		return byteTableToBinaryString(output);
	}
	public String AES3() {
		byte[][] output = byteTable;
		
		//return as string
		return byteTableToBinaryString(output);
	}
	public String AES4() {
		byte[][] output = byteTable;
		
		//return as string
		return byteTableToBinaryString(output);
	}
	
}
