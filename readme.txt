Benjamin McDonnell - c3166457 - University of Newcastle
COMP3260 Assignment 2 - 2019
AES encryption, decryption, and Avalanche effect

launch/Application.java contains the main entry point

ASSUMPTIONS
	Input text file is 2 lines, 128 characters per line, no spaces
	Every character of the input file is a 0 or a 1
	Line 1 is the Plaintext or Ciphertext
	Line 2 is the Key
	The given bytes are put into a matrix in a top-down left-right fashion, 
		eg the second byte of the input text will go into col 0 row 1
		This is how it was demonstrated to us in Lecture 7 Slide 30

NOTES
	Text input files are read from and written to the root folder (The folder this readme is in)
	The program will ask for input and output file names (with extensions)- If the output file already exists it will be overwritten!
	If you wish to store them in a folder they must be refered to in the program as "foldername/input.txt" - no quotes

Included some test text files

CONTENTS
	src
	---aes
	------AESHandler
	------RoundHandler
	------SBoxCalculator
	---analysis
	------StringAnalyser
	---cryption
	------Encrypter
	------Decrypter
	---helper
	------Converter
	---io
	------FileHandler
	---launch
	------Application
	
	Application.java contains the main entry point