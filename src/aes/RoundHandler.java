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
 *	'RoundHandler.java'
 *  File Description:
 *		Contains methods to transform a 2d int array in the various ways used in AES
 */
package aes;

import java.util.Arrays;

public class RoundHandler {
	SBoxCalculator sb;

	public RoundHandler() {
		sb = new SBoxCalculator();
	}
	
	public int[][] SubBytes(int[][] input) {
		int[][] output = new int[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = sb.sBox(input[i][j]);
			}
		}
		return output;
	}
	
	public int[][] ShiftRows(int[][] input) {
		int[][] output = new int[4][4];
		return output;
	}
	public int[][] MixColumns(int[][] input) {
		int[][] output = new int[4][4];
		return output;
	}
	public int[][] AddRoundKey(int[][] input) {
		int[][] output = new int[4][4];
		return output;
	}
}
