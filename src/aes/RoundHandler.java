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
	int[][][] allRoundKeys;
	int rcon;
	int[][] mixMatrix = {
		{2,3,1,1},
		{1,2,3,1},
		{1,1,2,3},
		{3,1,1,2}
	};
	int[][] inverseMixMatrix = {
		{14,11,13,9},
		{9,14,11,13},
		{13,9,14,11},
		{11,13,9,14}
	};

	public RoundHandler(int[][] key) {
		sb = new SBoxCalculator();
		rcon = 1; //counts up for every round key we use
		allRoundKeys = new int[11][4][4]; // 11 4x4 round keys
		generateRoundKeys(key);
	}
	
	public int[][] subBytes(int[][] input) { 
		/*
		 * Overloading to allow for default value of "false", call this method if encrypting
		 */
		return subBytes(input, false);
	}
	
	public int[][] subBytes(int[][] input, boolean decrypt) { 
		/*
		 * uses the sBox table from SBoxCalculator.java to substitute the input values into a new output table
		 * call with decrypt = true if decrypting, decrypt = false for encrypting, or just call the overloaded method 
		 */
		int[][] output = new int[4][4];
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = (!decrypt)? sb.sBox(input[i][j]) : sb.invertedSBox(input[i][j]); //regular sBox if encrypting, inverted sBox if decrypting
			}
		}
		return output;
	}
	
	public int[][] shiftRows(int[][] input) {
		/*
		 * Overloading to allow for default value of "false", call this method if encrypting
		 */
		return shiftRows(input, false);
	}
	
	public int[][] shiftRows(int[][] input, boolean decrypt) {
		/*
		 * shifts row 2 left by 1, row 3 left by 2, row 4 left by 3
		 * call with decrypt = true if decrypting, decrypt = false for encrypting, or just call the overloaded method 
		 */
		int[][] output = new int[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				if (i==0) { output[i][j] = input[i][j]; } //same for first row
				else {
					output[i][j] = (!decrypt)? input[i][(j+i)%4] : input[i][Math.floorMod(j-i, 4)]; //shift left if encrypting, shift right if decrypting --- floormod allows for negative LHS
				}
			}
		}
		return output;
	}
	
	public int[][] mixColumns(int[][] input) {
		/*
		 * Overloading to allow for default value of "false", call this method if encrypting
		 */
		return mixColumns(input,false);
	}
	
	public int[][] mixColumns(int[][] input, boolean decrypt) {
		/*
		 * call with decrypt = true if decrypting, decrypt = false for encrypting, or just call the overloaded method 
		 * Matrix multiplication between our input matrix and the given mixColumn matrix
		 * uses binMultiply to handle individual binary calculations, XORs the results
		 * From workshop 8 solutions
		 * Multiplication by 2 in GF(2^8) is equivalent to a left shift, dropping the top bit, and conditionally applying XOR with 0001 1011 (0x1b) if the multiplication causes overflow (if top bit was 1)
		 * Multiplication by 3 is equivalent to (multiplication by 2) + (multiplication by 1)
		 */
		int[][] output = new int[4][4];
		int[][] matrix = (!decrypt)? mixMatrix : inverseMixMatrix; //use the inverted mix column if we are decrypting
		for (int i = 0; i < 4; i++) {
				output[0][i] = (binMultiply(input[0][i], matrix[0][0])) ^ (binMultiply(input[1][i], matrix[0][1])) 
						^ (binMultiply(input[2][i], matrix[0][2])) ^ (binMultiply(input[3][i], matrix[0][3]));
				
				output[1][i] = (binMultiply(input[0][i], matrix[1][0])) ^ (binMultiply(input[1][i], matrix[1][1])) 
						^ (binMultiply(input[2][i], matrix[1][2])) ^ (binMultiply(input[3][i], matrix[1][3]));
				
				output[2][i] = (binMultiply(input[0][i], matrix[2][0])) ^ (binMultiply(input[1][i], matrix[2][1])) 
						^ (binMultiply(input[2][i], matrix[2][2])) ^ (binMultiply(input[3][i], matrix[2][3]));
				
				output[3][i] = (binMultiply(input[0][i], matrix[3][0])) ^ (binMultiply(input[1][i], matrix[3][1])) 
						^ (binMultiply(input[2][i], matrix[3][2])) ^ (binMultiply(input[3][i], matrix[3][3]));
		}
		return output;
	}
	
	public int binMultiply(int a, int b) {
		/*
		 * Binary multiplication of two integers
		 * Works only for multiplying by 1 2 or 3, and 9, 11, 13, 14 - as that is all we need for this task
		 */
		
		//case multiplying by 1
		if (b == 1) {return a;} //a * 1 = a
		int result = 0;
		
		//case multiplying by 2 or 3
		if (b==2 || b==3) {
			result = a << 1; // a * 2 = a leftshifted by 1
			if (a >= 128) { //if int is >= 128 then it has a '1' in the leftmost column as a binary digit, so we must XOR it with binary 11011 (as described in workshop)
				result = result ^ 0x1b;
			}
		}
		
		//case multiplying by 3
		if (b == 3) {result = result ^ a;} // a * 3 = (a * 2) + a
		
		else if (b==9) {result = binMultiply(binMultiply(binMultiply(a,2),2),2) ^ a;} // a * 9 === (((a * 2) * 2) * 2) + a
		else if (b==11) {result = binMultiply(binMultiply(binMultiply(a,2),2) ^ a,2) ^ a;} // a * 11 === ((((a * 2) * 2) + a) * 2) + a
		else if (b==13) {result = binMultiply(binMultiply(binMultiply(a,2) ^ a,2),2) ^ a;} // a * 13 === ((((a * 2) + a) * 2) * 2) + a
		else if (b==14) {result = binMultiply(binMultiply(binMultiply(a,2) ^ a,2) ^ a,2);} // a * 14 ==== ((((a * 2) + a) * 2) + a) * 2
		
		return result % 0x100; //result can't be greater than 2 hex digits, so modulo it with 256
	}
	
	/*
	 * Decryption and Encryption the same for round key, we just use the keys in inverse order to decrypt
	 */
	public void generateRoundKeys(int[][] key) {
		/*
		 * Sets the internal variable allRoundKeys[][][], an array containing 11 4x4 round keys
		 */
		allRoundKeys[0] = key; //first key is given, used for round 0
		for (int i = 1; i < 11; i++) { //for round keys 1 to 10
			int[][] newKey = new int[4][4]; //a new empty 4x4 key
			
			//take last column of previous key as the first key of this one
			for (int j = 0; j < 4; j++) {
				newKey[j][0] = allRoundKeys[i-1][j][3];
			}
			
			//shift top of column to bottom
			int tempInt = newKey[0][0];
			newKey[0][0] = newKey[1][0];
			newKey[1][0]= newKey[2][0];
			newKey[2][0] = newKey[3][0];
			newKey[3][0] = tempInt;
			
			//apply subBytes to new column
			for (int j = 0; j < 4; j++) {
				newKey[j][0] = sb.sBox(newKey[j][0]);
			}
			
			//new column = 1st old column XOR this column XOR Column with [rcon][0][0][0]
			for (int j = 0; j < 4; j++) {
				newKey[j][0] = allRoundKeys[i-1][j][0] ^ newKey[j][0] ^ ((j == 0)?rcon:0);
			}
			
			//double rcon in GF(2^8) --- should go (in hex) 01 02 04 08 10 20 40 80 1b 36
			rcon = (rcon<<1) ^ (0x11b & -(rcon>>7)); //see ref 1
			rcon %= 0x100; //trim to 2 places
			
			//second new column = 1st new column XOR old 2nd column
			//third new column = 2nd new column XOR old 3rd column
			//fourth new column = 3rd new column XOR old 4th column
			for (int j = 1; j < 4; j++) {
				for (int k=0; k < 4; k++) {
					newKey[k][j] = allRoundKeys[i-1][k][j] ^ newKey[k][j-1];
				}
			}
			
			//Copy this key onto the appropriate allRoundKeys key
			for(int j = 0; j < 4; j++) {
				for (int k = 0; k < 4; k++) {
					allRoundKeys[i][j][k] = newKey[j][k];
				}
			}
			
		}
	}
	public int[][] addRoundKey(int[][] input, int round) {
		/*
		 *  Calls makeRoundKey to get the round key for this round (round 0 to 10)
		 *  Adds it to the input matrix
		 */
		
		//output = input XOR roundkey
		int[][] output = new int[4][4];
		for (int i=0; i < 4; i++) {
			for (int j=0; j < 4; j++) {
				output[i][j] = input[i][j] ^ allRoundKeys[round][i][j];
			}
		}
		return output;
	}
	
	/*
	public void makeRoundKey(int[][] key) {
		/*
		 * OVERWRITES THE GIVEN KEY
		 * Follows the steps to create a new round key for this iteration
		 * STEPS:
		 */
	/*
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
	} */
}
