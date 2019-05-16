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
 *
 *	References:
 *		ref 1 - doubling rcon in GF(2^8): https://crypto.stackexchange.com/questions/2418/how-to-use-rcon-in-key-expansion-of-128-bit-advanced-encryption-standard
 */
package aes;

public class RoundHandler {
	SBoxCalculator sb;
	int rcon;
	boolean debugOnce = true;
	int[][] mixMatrix = {
		{2,3,1,1},
		{1,2,3,1},
		{1,1,2,3},
		{3,1,1,2}
	};

	public RoundHandler() {
		sb = new SBoxCalculator();
		rcon = 1; //counts up for every round key we use
	}
	
	public int[][] subBytes(int[][] input) {
		/*
		 * uses the sBox table from SBoxCalculator.java to substitute the input values into a new output table
		 */
		int[][] output = new int[4][4];
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = sb.sBox(input[i][j]);
			}
		}
		return output;
	}
	
	public int[][] shiftRows(int[][] input) {
		/*
		 * shifts row 2 left by 1, row 3 left by 2, row 4 left by 3
		 */
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
	
	public int[][] mixColumns(int[][] input) {
		/*
		 * Matrix multiplication between our input matrix and the given mixColumn matrix
		 * uses binMultiply to handle individual binary calculations, XORs the results
		 * From workshop 8 solutions
		 * Multiplication by 2 in GF(2^8) is equivalent to a left shift, dropping the top bit, and conditionally applying XOR with 0001 1011 (0x1b) if the multiplication causes overflow (if top bit was 1)
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
		 * Works only for multiplying by 1 2 or 3, as that is all we need for this task
		 */
		
		//case multiplying by 1
		if (b == 1) {return a;}
		int result = 0;
		
		//case multiplying by 2 or 3
		result = a << 1; //leftshift by 1, effectively multiplication by 2 in this context
		if (a >= 128) { //if int is >= 128 then it has a 1 in the leftmost column as a binary digit
			result = result ^ 0x1b;
		}
		
		//case multiplying by 3
		if (b == 3) {result = result ^ a;}
		
		return result % 0x100; //result can't be greater than 2 hex digits, so modulo it with 256
	}
	
	public int[][] addRoundKey(int[][] input, int[][] key) {
		/*
		 *  Calls makeRoundKey to get the round key for this iteration
		 *  Adds it to the input matrix
		 */
		//convert key to roundkey for this iteration
		makeRoundKey(key); //MANIPULATES ORIGINAL TABLE
		
		//output = input XOR roundkey
		int[][] output = new int[4][4];
		for (int i=0; i < 4; i++) {
			for (int j=0; j < 4; j++) {
				output[i][j] = input[i][j] ^ key[i][j];
			}
		}
		return output;
	}
	
	public void makeRoundKey(int[][] key) {
		/*
		 * OVERWRITES THE GIVEN KEY
		 * Follows the steps to create a new round key for this iteration
		 * STEPS:
		 */
		//take last column of key as first column of newKey
		int[][] newKey = new int[4][4];
		for (int i=0; i < 4; i++) {
			newKey[i][0] = key[i][3];
		}
		
		//System.out.println("\nDEBUG -- before shifting top of column to bottom: \n"+Integer.toHexString(newKey[0][0])+"\n"+Integer.toHexString(newKey[1][0])+"\n"+Integer.toHexString(newKey[2][0])+"\n"+Integer.toHexString(newKey[3][0])+"\n");
		
		//move top val to bottom of new column
		int tempInt = newKey[0][0];
		newKey[0][0] = newKey[1][0];
		newKey[1][0]= newKey[2][0];
		newKey[2][0] = newKey[3][0];
		newKey[3][0] = tempInt;
		
		//Apply subBytes to new column
		for (int i = 0; i < 4; i++) {
			newKey[i][0] = sb.sBox(newKey[i][0]);
		}
		
		//new column = 1st old column XOR this column XOR Column with [rcon][0][0][0]
		for (int i = 0; i < 4; i++) {
			newKey[i][0] = key[i][0] ^ newKey[i][0] ^ ((i == 0)?rcon:0);
		}
		
		//double rcon in GF(2^8) --- should go (in hex) 01 02 04 08 10 20 40 80 1b 36 --- does this automatically trim to 2 places?
		rcon = (rcon<<1) ^ (0x11b & -(rcon>>7)); //see ref 1
		rcon %= 0x100; //trim to 2 places
		
		//second new column = 1st new column XOR old 2nd column
		//third new column = 2nd new column XOR old 3rd column
		//fourth new column = 3rd new column XOR old 4th column
		for (int i = 1; i < 4; i++) {
			for (int j=0; j < 4; j++) {
				newKey[j][i] = key[j][i] ^ newKey[j][i-1];
			}
		}
		
		//copy over newKey to overwrite key
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				key[i][j] = newKey[i][j];
			}
		}
	}
}
