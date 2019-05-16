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
	int[][] keyTable;
	
	public AESHandler(String input, String key) {
		this.input = input;
		this.key=key;
		intTable = binaryStringToIntTable(input);
		keyTable = binaryStringToIntTable(key);
		
		//debugTest();//DEBUG
	}
	
	/*
	 * CONVERSIONS - currently assumes table is read top to bottom then left to right, might change later
	 * eg - the first 4 numbers in the text file represent column 1
	 */
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
	
	public String[] AES0() {
		/*
		 * The standard AES,initial addRound key --- then 9 rounds of sub, shift, mix --- then a final round of sub,shift
		 * returns a string array length 11 with each value being the output plaintext string after each step (0-10)
		 */
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		int[][] currKeyTable = new int[4][4];
		
		outputArray[0] = intTableToBinaryString(intTable); //initial
		
		//XOR initial key to the output table as step 1, ***this includes the initial round***
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j] ^ keyTable[i][j]; //initial round XORs keyTable
				currKeyTable[i][j] = keyTable[i][j];
			}
		}
		
		//get a roundhandler instance for the remaining rounds
		RoundHandler rh = new RoundHandler();
		
		//loop 9 times
		for (int i = 0; i < 9; i++) {
			output = rh.subBytes(output);
			output = rh.shiftRows(output);
			output = rh.mixColumns(output);
			output = rh.addRoundKey(output,currKeyTable);
			
			outputArray[i+1] = intTableToBinaryString(output);
		}
		
		//final run through
		output = rh.subBytes(output);
		output = rh.shiftRows(output);
		output = rh.addRoundKey(output,currKeyTable);
		
		outputArray[10] = intTableToBinaryString(output);
		
		/*
		//DEBUG print as hex table
		System.out.println("Printing result as hex table: ");
		for (int i = 0; i < 4; i++) {
			String line = "";
			for (int j = 0; j < 4; j++) {
				line += Integer.toHexString(output[i][j]) + " ";
			}
			System.out.println(line);
		}
		*/
		
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
		int[][] currKeyTable = new int[4][4];
		
		outputArray[0] = intTableToBinaryString(intTable); //initial
		
		//XOR initial key to the output table as step 1, ***this includes the initial round***
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j] ^ keyTable[i][j]; //initial round XORs keyTable
				currKeyTable[i][j] = keyTable[i][j];
			}
		}
		
		//get a roundhandler instance for the remaining rounds
		RoundHandler rh = new RoundHandler();
		
		//loop 9 times -- NO SUBSTITUTE BYTES STEP
		for (int i = 0; i < 9; i++) {
			output = rh.shiftRows(output);
			output = rh.mixColumns(output);
			output = rh.addRoundKey(output,currKeyTable);
			
			outputArray[i+1] = intTableToBinaryString(output);
		}
		
		//final run through -- NO SUBSTITUTE BYTES STEP
		output = rh.shiftRows(output);
		output = rh.addRoundKey(output,currKeyTable);
		
		outputArray[10] = intTableToBinaryString(output);
		
		return outputArray;
	}
	
	
	public String[] AES2() {
		/*
		 * AES0 without ShiftRows step
		 */
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		int[][] currKeyTable = new int[4][4];
		
		outputArray[0] = intTableToBinaryString(intTable); //initial
		
		//XOR initial key to the output table as step 1, ***this includes the initial round***
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j] ^ keyTable[i][j]; //initial round XORs keyTable
				currKeyTable[i][j] = keyTable[i][j];
			}
		}
		
		//get a roundhandler instance for the remaining rounds
		RoundHandler rh = new RoundHandler();
		
		//loop 9 times -- NO SHIFT ROWS STEP
		for (int i = 0; i < 9; i++) {
			output = rh.subBytes(output);
			output = rh.mixColumns(output);
			output = rh.addRoundKey(output,currKeyTable);
			
			outputArray[i+1] = intTableToBinaryString(output);
		}
		
		//final run through -- NO SHIFT ROWS STEP
		output = rh.subBytes(output);
		output = rh.addRoundKey(output,currKeyTable);
		
		outputArray[10] = intTableToBinaryString(output);
		
		return outputArray;
	}
	
	
	public String[] AES3() {
		/*
		 * AES0 without mixColumns step
		 */
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		int[][] currKeyTable = new int[4][4];
		
		outputArray[0] = intTableToBinaryString(intTable); //initial
		
		//XOR initial key to the output table as step 1, ***this includes the initial round***
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j] ^ keyTable[i][j]; //initial round XORs keyTable
				currKeyTable[i][j] = keyTable[i][j];
			}
		}
		
		//get a roundhandler instance for the remaining rounds
		RoundHandler rh = new RoundHandler();
		
		//loop 9 times -- NO MIX COLUMNS STEP
		for (int i = 0; i < 9; i++) {
			output = rh.subBytes(output);
			output = rh.shiftRows(output);
			output = rh.addRoundKey(output,currKeyTable);
			
			outputArray[i+1] = intTableToBinaryString(output);
		}
		
		//final run through
		output = rh.subBytes(output);
		output = rh.shiftRows(output);
		output = rh.addRoundKey(output,currKeyTable);
		
		outputArray[10] = intTableToBinaryString(output);
		
		return outputArray;
	}
	
	
	public String[] AES4() {
		/*
		 * AES0 without Add round key step
		 */
		//copy intTable to output and keyTable to currKeyTable -- so we don't mess up the tables for other AES runs
		String[] outputArray = new String[11];
		int[][] output = new int[4][4];
		int[][] currKeyTable = new int[4][4];
		
		outputArray[0] = intTableToBinaryString(intTable); //initial
		
		//XOR initial key to the output table as step 1, ***this includes the initial round***
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				output[i][j] = intTable[i][j] ^ keyTable[i][j]; //initial round XORs keyTable
				currKeyTable[i][j] = keyTable[i][j];
			}
		}
		
		//get a roundhandler instance for the remaining rounds
		RoundHandler rh = new RoundHandler();
		
		//loop 9 times -- NO ADD ROUND KEY STEP
		for (int i = 0; i < 9; i++) {
			output = rh.subBytes(output);
			output = rh.shiftRows(output);
			output = rh.mixColumns(output);
			
			outputArray[i+1] = intTableToBinaryString(output);
		}
		
		//final run through -- NO ADD ROUND KEY STEP
		output = rh.subBytes(output);
		output = rh.shiftRows(output);
		
		outputArray[10] = intTableToBinaryString(output);
		
		return outputArray;
	}
	
	public void debugTest() {
		System.out.println("\ninput plaintext: "+input+"\n");
		System.out.println("input key: "+key+"\n");
		RoundHandler rh = new RoundHandler();
		
		System.out.println("input plaintext as hex table: ");
		for (int i = 0; i < 4; i++) {
			String line = "";
			for (int j = 0; j < 4; j++) {
				line += Integer.toHexString(intTable[i][j]) + " ";
			}
			System.out.println(line);
		}
		System.out.println("\ninput key as hex table: ");
		for (int i = 0; i < 4; i++) {
			String line = "";
			for (int j = 0; j < 4; j++) {
				line += Integer.toHexString(keyTable[i][j]) + " ";
			}
			System.out.println(line);
		}
		
		
		
		
		System.out.println("\n-------------------\n");
		
		//XOR initial key to the output table as step 1, ***this includes the initial round***
		for (int i=0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				intTable[i][j] = intTable[i][j] ^ keyTable[i][j]; //initial round XORs keyTable
			}
		}
		System.out.println("plaintext after XOR with key, as hex table: ");
		for (int i = 0; i < 4; i++) {
			String line = "";
			for (int j = 0; j < 4; j++) {
				line += Integer.toHexString(intTable[i][j]) + " ";
			}
			System.out.println(line);
		}
		
		rh.addRoundKey(intTable, keyTable);
		
		System.out.println("\nkey after 1 roundkey, as hex table: ");
		for (int i = 0; i < 4; i++) {
			String line = "";
			for (int j = 0; j < 4; j++) {
				line += Integer.toHexString(keyTable[i][j]) + " ";
			}
			System.out.println(line);
		}
	}
}
