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

public class RoundHandler {
	SBoxCalculator sb;
	int[][] mixMatrix = {
		{2,3,1,1},
		{1,2,3,1},
		{1,1,2,3},
		{3,1,1,2}
	};

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
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				if (i==0) { output[i][j] = input[i][j]; } //same for first row
				else {
					output[i][j] = input[i][(j+i)%4];
				}
			}
		}
		return output;
	}
	
	public int[][] MixColumns(int[][] input) {
		/*
		 * From workshop 8 solutions
		 * Multiplication by 2 in GF(2^8) is equivalent to a left shift, dropping the top bit, and conditionally applying XOR with 0001 1011 (0x1b) if the multiplication causes overflow
		 * Multiplication by 3 is equivalent to (multiplication by 2) + (multiplication by 1)
		 */
		int[][] output = new int[4][4];
		for (int i = 0; i < 4; i++) {
				output[0][i] = (binMultiply(input[0][i], mixMatrix[0][0])) ^ (binMultiply(input[1][i], mixMatrix[0][1])) 
						^ (binMultiply(input[2][i], mixMatrix[0][2])) ^ (binMultiply(input[3][i], mixMatrix[0][3]));
				
				output[1][i] = (binMultiply(input[0][i], mixMatrix[1][0])) ^ (binMultiply(input[1][i], mixMatrix[1][1])) 
						^ (binMultiply(input[2][i], mixMatrix[1][2])) ^ (binMultiply(input[3][i], mixMatrix[1][3]));
				
				output[2][i] = (binMultiply(input[0][i], mixMatrix[2][0])) ^ (binMultiply(input[1][i], mixMatrix[2][1])) 
						^ (binMultiply(input[2][i], mixMatrix[2][2])) ^ (binMultiply(input[3][i], mixMatrix[2][3]));
				
				output[3][i] = (binMultiply(input[0][i], mixMatrix[3][0])) ^ (binMultiply(input[1][i], mixMatrix[3][1])) 
						^ (binMultiply(input[2][i], mixMatrix[3][2])) ^ (binMultiply(input[3][i], mixMatrix[3][3]));
		}
		
		return output;
	}
	
	public int binMultiply(int a, int b) {
		/*
		 * Binary multiplication of two integers
		 * Works only for multiplying by 1 2 or 3
		 */
		
		//case multiplying by 1
		if (b == 1) {return a;}
		int result = 0;
		
		//case multiplying by 2 or 3
		result = a << 1; //leftshift by 1
		if (a >= 128) { //if int is >= 128 then it has a 1 in the leftmost column as a binary digit
			result = result ^ 0x1b;
		}
		
		//case multiplying by 3
		if (b == 3) {result = result ^ a;}
		
		return result % 0x100; //result can't be greater than 2 hex digits, so modulo it with 256
	}
	
	public int[][] AddRoundKey(int[][] input) {
		int[][] output = new int[4][4];
		return output;
	}
}
