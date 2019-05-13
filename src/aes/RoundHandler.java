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
 *		description here
 */
package aes;

public class RoundHandler {

	public RoundHandler() {}
	
	public byte[][] SubBytes(byte[][] input) {
		byte[][] output = input;
		return output;
	}
	public byte[][] ShiftRows(byte[][] input) {
		byte[][] output = input;
		return output;
	}
	public byte[][] MixColumns(byte[][] input) {
		byte[][] output = input;
		return output;
	}
	public byte[][] AddRoundKey(byte[][] input) {
		byte[][] output = input;
		return output;
	}
}
