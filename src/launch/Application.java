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
 *	'Application.java'
 *  File Description:
 *		The main file for the program. Takes input, runs encryption, outputs results 
 *
 */

package launch;

import java.util.concurrent.TimeUnit;

import aes.AESHandler;
import io.FileHandler;
import analysis.StringAnalyser;

public class Application {
	public static void main(String[] args) {
		FileHandler ih = new FileHandler();  //runs ih.init() which Handles prompt, sets text/key
		StringAnalyser sa = new StringAnalyser(); //used for analysis the bit difference of 2 strings
		
		long startTime = System.nanoTime(); //get the time at start (after file prompt/handle)
		String P = ih.getText(); //The input plaintext from file, P
		String K = ih.getKey(); //The input key from file, K
		
		//Data storage for the P_i and K_i result strings
		String[][][] allP_iResults = new String[128][5][11]; //3 dimensional array of strings [P_i 0-127][AES 0-4][round 0 - 11]
		String[][][] allK_iResults = new String[128][5][11]; //3 dimensional array of strings [K_i 0-127][AES 0-4][round 0 - 11]
		
		//Data storage for the average difference between P and P_i after each round for each AES
		double[][] avgDifferenceP = new double[5][11];
		
		//Data storage for the average difference between P under K and P under K_i
		double[][] avgDifferenceK = new double[5][11];
		
		
		//Get AES results for original P
		AESHandler aeshandler1 = new AESHandler(P,K);
		String[][] originalResults = new String[5][11]; //the results of the original P under K
		originalResults[0] = aeshandler1.AES0(); //results of each round of AES0 on original P
		originalResults[1] = aeshandler1.AES1(); //results of each round of AES1 on original P
		originalResults[2] = aeshandler1.AES2(); //results of each round of AES2 on original P
		originalResults[3] = aeshandler1.AES3(); //results of each round of AES3 on original P
		originalResults[4] = aeshandler1.AES4(); //results of each round of AES4 on original P
		
		/*
		 * P_i
		 */
		//GET AES results for P_i under K from i = 0 to 127, where P_i is P with 1 differing bit at index i
		for (int i = 0; i < 128; i++) {	
			String ithLetter = (P.substring(i,i+1).equals("0"))? "1" : "0"; // Get the ith letter of P, swap 0 for 1 or vice versa
			String P_i = (i==0)? ithLetter + P.substring(1) : P.substring(0,i) + ithLetter + P.substring(i+1); //replace the ithLetter of P with the new opposite one, this is now P_i
			AESHandler tempHandler = new AESHandler(P_i,K); //create an aes handler for this P_i under K
			allP_iResults[i][0] = tempHandler.AES0(); //store the results of AES0 for this P_i under K
			allP_iResults[i][1] = tempHandler.AES1(); //store the results of AES1 for this P_i under K
			allP_iResults[i][2] = tempHandler.AES2(); //etc
			allP_iResults[i][3] = tempHandler.AES3(); 
			allP_iResults[i][4] = tempHandler.AES4(); 
		}
		
		//Get the average bit difference between P and P_i for i = 0 to 127, for each round, under each AES type
		for(int k = 0; k < 5; k++) { //for each AES type
			for (int i = 0; i < 11; i++) { //for each round
				avgDifferenceP[k][i] = 0;
				for (int j = 0; j < 128; j++) { //for each P_i
					avgDifferenceP[k][i] +=  sa.getDifferenceInBinaryStrings(originalResults[k][i], allP_iResults[j][k][i]);
				}
				avgDifferenceP[k][i] /= 128.0;
			}
		}
		
		/*
		 * K_i
		 */
		//GET AES results for P under K_i from i = 0 to 127, where K_i is K with 1 differing bit at index i
		for (int i = 0; i < 128; i++) {	
			String ithLetter = (K.substring(i,i+1).equals("0"))? "1" : "0"; // Get the ith letter of K, swap 0 for 1 or vice versa
			String K_i = (i==0)? ithLetter + K.substring(1) : K.substring(0,i) + ithLetter + K.substring(i+1); //replace the ithLetter of K with the new opposite one, this is now P_i
			AESHandler tempHandler = new AESHandler(P,K_i); //create an aes handler for this P under K_i
			allK_iResults[i][0] = tempHandler.AES0(); //store the results of AES0 for this P under K_i 
			allK_iResults[i][1] = tempHandler.AES1(); //store the results of AES1 for this P under K_i 
			allK_iResults[i][2] = tempHandler.AES2(); //etc
			allK_iResults[i][3] = tempHandler.AES3();
			allK_iResults[i][4] = tempHandler.AES4();
		}
		
		//Get the average bit difference between P under K and P under K_i for i = 0 to 127, for each round, under each AES type
		for(int k = 0; k < 5; k++) { //for each AES type
			for (int i = 0; i < 11; i++) { //for each round
				avgDifferenceK[k][i] = 0;
				for (int j = 0; j < 128; j++) { //for each P_i
					avgDifferenceK[k][i] +=  sa.getDifferenceInBinaryStrings(originalResults[k][i], allK_iResults[j][k][i]);
				}
				avgDifferenceK[k][i] /= 128.0;
			}
		}
		
		//DEBUG PRINT RESULTS
		System.out.println("ENCRYPTION");
		System.out.println("Plaintext P: "+ih.getText());
		System.out.println("CIPHERTEXT: "+originalResults[0][10]); //AES0 after all 10 rounds
		System.out.println("Key K: "+ih.getKey());
		
		System.out.println("Running time: "+TimeUnit.NANOSECONDS.toMillis((System.nanoTime() - startTime))+"ms"); //take the start time from the current time to get time elapsed in milliseconds
		System.out.println("Avalanche:");
		System.out.println("P and Pi under K");
		
		//Print the results table for P and P_i under K - Note averages are rounded to nearest whole number (eg 5.75 => 6)
		System.out.printf("%-10s %-10s %-10s %-10s %-10s %-10s\n","Round", "AES0", "AES1", "AES2", "AES3", "AES4");
		for (int i = 0; i < 11; i++) {
			System.out.printf("%-10d %-10.0f %-10.0f %-10.0f %-10.0f %-10.0f\n", i, avgDifferenceP[0][i], avgDifferenceP[1][i], avgDifferenceP[2][i], avgDifferenceP[3][i], avgDifferenceP[4][i]);
		}
		
		System.out.println("\nP under K and Ki");
		
		//Print the results table for P under K and P under K_i - Note averages are rounded to nearest whole number (eg 5.75 => 6)
		System.out.printf("%-10s %-10s %-10s %-10s %-10s %-10s\n","Round", "AES0", "AES1", "AES2", "AES3", "AES4");
		for (int i = 0; i < 11; i++) {
			System.out.printf("%-10d %-10.0f %-10.0f %-10.0f %-10.0f %-10.0f\n", i, avgDifferenceK[0][i], avgDifferenceK[1][i], avgDifferenceK[2][i], avgDifferenceK[3][i], avgDifferenceK[4][i]);
		}
		
		System.out.println("\nExiting program...");
	}
}
