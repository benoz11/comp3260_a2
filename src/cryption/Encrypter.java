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
 *
 *	'Encrypter.java'
 *  File Description:
 *  	Reads the file given by the user - read the assumptions section for more specific info on the file requirements
 *		The system will run AES on this data and produce an encrypted ciphertext based on P and K
 *		The system will run 4 addition similar AES methods each missing a step
 *		The system will then run 128 additional Plaintexts that each differ from P by exactly 1 bit under the original K
 *			and calculate the average difference in bits after each round, for each AES method
 *		The system will then run the original P under 128 additional Keys that each differ from K by exactly 1 bit
 *			and calculate the average difference in bits after each round, for each AES method
 *		The results will be exported to the output file as a readable table showing the average difference between all 128 for each round for each AES
 *
 *	ASSUMPTIONS: 
 *  	input file is given in its full name, eg "input.txt" without quotes
 *  	input file is in the root of this project (COMP3260_A2_c3166457), or has its subfolder specified in the string eg "inputs/test.txt" without quotes
 *  	input file contains 2 lines, 128 characters long, containing only either 0's or 1's
 *  	input file line 1 is the plaintext, line 2 is the key
 *  	output file will be placed in this root folder unless its subfolder is specified in this string
 *  	
 *  NOTES:
 *  	output file will be overwritten if it already exists
 */
package cryption;

import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import aes.AESHandler;
import aes.RoundHandler;
import analysis.StringAnalyser;
import helper.Converter;
import io.FileHandler;

public class Encrypter {

	public Encrypter() {
		init();
	}
	
	public void init() {
		FileHandler fh = new FileHandler();  //runs ih.init() which Handles input file prompt prompt, sets text/key
		StringAnalyser sa = new StringAnalyser(); //used for analysis the bit difference of 2 strings
		Converter converter = new Converter();
		
		System.out.println("Please enter the output file name");
		String outputFilename = fh.getFilename();
		
		System.out.println("\nProcessing...");
		
		long startTime = System.nanoTime(); //get the time at start (after file prompt/handle)
		String P = fh.getText(); //The input plaintext from file, P
		String K = fh.getKey(); //The input key from file, K
		RoundHandler rh = new RoundHandler(converter.binaryStringToIntTable(K)); //new round handler on key K
		
		
		//Data storage for the P_i and K_i result strings
		String[][][] allP_iResults = new String[128][5][11]; //3 dimensional array of strings [P_i 0-127][AES 0-4][round 0 - 11]
		String[][][] allK_iResults = new String[128][5][11]; //3 dimensional array of strings [K_i 0-127][AES 0-4][round 0 - 11]
		
		//Data storage for the average difference between P and P_i after each round for each AES
		double[][] avgDifferenceP = new double[5][11];
		
		//Data storage for the average difference between P under K and P under K_i
		double[][] avgDifferenceK = new double[5][11];
		
		
		//Get AES results for original P
		AESHandler aeshandler = new AESHandler(P,K,rh);
		String[][] originalResults = new String[5][11]; //the results of the original P under K
		originalResults[0] = aeshandler.AES0(); //results of each round of AES0 on original P
		originalResults[1] = aeshandler.AES1(); //results of each round of AES1 on original P
		originalResults[2] = aeshandler.AES2(); //results of each round of AES2 on original P
		originalResults[3] = aeshandler.AES3(); //results of each round of AES3 on original P
		originalResults[4] = aeshandler.AES4(); //results of each round of AES4 on original P
		
		/*
		 * P_i
		 */
		//GET AES results for P_i under K from i = 0 to 127, where P_i is P with 1 differing bit at index i
		for (int i = 0; i < 128; i++) {	
			String ithLetter = (P.substring(i,i+1).equals("0"))? "1" : "0"; // Get the ith letter of P, swap 0 for 1 or vice versa
			String P_i = (i==0)? ithLetter + P.substring(1) : P.substring(0,i) + ithLetter + P.substring(i+1); //replace the ithLetter of P with the new opposite one, this is now P_i
			AESHandler tempHandler = new AESHandler(P_i,K,rh); //create an aes handler for this P_i under K
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
			rh = new RoundHandler(converter.binaryStringToIntTable(K_i));
			AESHandler tempHandler = new AESHandler(P,K_i,rh); //create an aes handler for this P under K_i NEEDS TO BE DONE ON EACH ITERATION, AS EACH NEW K HAS ITS OWN SET OF ROUND KEYS
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
		
		//Create arraylist of strings representing each line to write to the file
		ArrayList<String> outputLines = new ArrayList<>();
		outputLines.add("ENCRYPTION");
		outputLines.add("Plaintext P: "+P);
		outputLines.add("Key K: "+K);
		outputLines.add("Ciphertext C: "+originalResults[0][10]); //AES0 after all 10 rounds
		outputLines.add("Running time: "+TimeUnit.NANOSECONDS.toMillis((System.nanoTime() - startTime))+"ms"); //take the start time from the current time to get time elapsed in milliseconds
		outputLines.add("Avalanche:");
		outputLines.add("P and Pi under K");
		outputLines.add(String.format("%-10s %-10s %-10s %-10s %-10s %-10s","Round", "AES0", "AES1", "AES2", "AES3", "AES4"));
		
		//Print the results table for P and P_i under K - Note averages are rounded to nearest whole number (eg 5.75 => 6)
		for (int i = 0; i < 11; i++) {
			outputLines.add(String.format("%-10d %-10.0f %-10.0f %-10.0f %-10.0f %-10.0f", i, avgDifferenceP[0][i], avgDifferenceP[1][i], avgDifferenceP[2][i], avgDifferenceP[3][i], avgDifferenceP[4][i]));
		}
		
		outputLines.add("\nP under K and Ki");
		
		//Print the results table for P under K and P under K_i - Note averages are rounded to nearest whole number (eg 5.75 => 6)
		outputLines.add(String.format("%-10s %-10s %-10s %-10s %-10s %-10s","Round", "AES0", "AES1", "AES2", "AES3", "AES4"));
		for (int i = 0; i < 11; i++) {
			outputLines.add(String.format("%-10d %-10.0f %-10.0f %-10.0f %-10.0f %-10.0f", i, avgDifferenceK[0][i], avgDifferenceK[1][i], avgDifferenceK[2][i], avgDifferenceK[3][i], avgDifferenceK[4][i]));
		}

		fh.writeToFile(outputLines,outputFilename); //write to file
		
		System.out.println("\nProcess complete! Results written to "+outputFilename);
		
		
		//DEBUG PRINT RESULTS 
		/*
		System.out.println("ENCRYPTION");
		System.out.println("Plaintext P: "+P);
		System.out.println("CIPHERTEXT: "+originalResults[0][10]); //AES0 after all 10 rounds
		System.out.println("Key K: "+K);
		
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
		*/
	}
}
