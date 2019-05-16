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
 *	'StringAnalyser.java'
 *  File Description:
 *		Simple class holding a method to compare binary strings of equal length
 *		It is used to compare the avalanche effect caused by subtle changes in P and K
 */
package analysis;

public class StringAnalyser {
	public int getDifferenceInBinaryStrings(String a, String b) {
		/*
		 * Returns the number of bits in binary string a that are different to binary string b
		 * Assumes a and b are same length
		 */
		int count = 0;
		char[] c1 = a.toCharArray();
		char[] c2 = b.toCharArray();
		for (int i = 0; i < c1.length; i++) {
			if (c1[i] != c2[i]) count++;
		}
		return count;
	}
}
