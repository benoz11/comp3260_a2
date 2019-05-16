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
 *	'FileHandler.java'
 *  File Description:
 *		Handles the logic related to file input
 *		Init() handles user prompt and sets its variables
 *		Simple call get methods to get the results of the file handling 
 */
package io;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class FileHandler {
	String text;
	String key;
	
	public FileHandler() {
		init(); //cleaner execution
	}
	
	public void init() {
		/*
		 * Prompts user for file name, sets text and key values if successful
		 * Handles errors correctly to either loop for a valid file or exit with error message
		 * After creating the object, get methods can be safely called as they are never null
		 * try-with-resources automatically closes the filescanner
		 */
		boolean success = false;
		while (!success) { //loop until we are given a valid file
			System.out.println("Please enter the input file name: ");
			try (Scanner fileScanner = new Scanner(new File(getFilename()))) { //throws FileNotFoundException if file cannot be found
				text = fileScanner.nextLine(); //set variables to file line contents, throws NoSuchElementException if file doesn't have nextLine()
				key = fileScanner.nextLine();
				success = true;
			} catch (FileNotFoundException fe) {
				System.out.println("File not found. Try again.");
			} catch (NoSuchElementException ne) {
				System.out.println("File does not follow the correct two line conventions. Check the input file and try again");
				System.exit(0);
			} catch (Exception e) { //Some other error, print stack trace to see why
				e.printStackTrace();
				System.exit(0);
			}
			//By this point the system has either set text and key to values OR exited due to error
		}
		//System.out.println("File successfully opened and read.");
		System.out.println();
	}

	@SuppressWarnings("resource") //System.in scanner doesn't need to be closed
	public String getFilename() {
		/*
		 * Get a string input from user, returns the string
		 * Does not close the Scanner as this causes issues when using System.in
		 */
		Scanner sc = new Scanner(System.in);
		String filename = sc.next();
		return filename;
	}
	
	public void writeToFile(ArrayList<String> contents, String filename) {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) { //try-with-resources will close the writer
			for(String line : contents) {
				writer.append(line+"\n");
			}
			
		} catch (IOException ie) {
			System.out.println("IO Error!");
			ie.printStackTrace();
		} catch (Exception e) {
			System.out.println("Misc Error!");
			e.printStackTrace();
		}
	}
	
	//GETTERS
	public String getText() {return text;}
	public String getKey() {return key;}

}
