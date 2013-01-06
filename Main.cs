/*
 * author: martani (martani.net@gmail.com)
 * copyright 2013
 * 
 */
using System;

namespace PaddingOracle
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			Console.WriteLine ("Padding Oracle Attack!");
			
			//To use the online Oracle uncomment this
			/*
			Oracles.ICBCOracle cbcOracle = new Oracles.OnlineCBCOracle();
			PaddingOracleAttacker attacker = new PaddingOracleAttacker(cbcOracle);
			string cipherHex = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4";
			byte[] cipher = Helpers.ConvertHexStringToByteArray(cipherHex);
			*/
			
			
			//To use a local Oracle uncomment this
			
			Oracles.AES_CBCOracle aes = new Oracles.AES_CBCOracle ();
			PaddingOracleAttacker attacker = new PaddingOracleAttacker (aes);
			string clearText = "And what, Socrates, is the food of the soul? Surely, I said, knowledge is the food of the soul. -- Plato";
			byte[] cipher = aes.AES_EncryptString (clearText);
			
			
			string plainText = attacker.Decrypt (cipher);			
			Console.WriteLine ("\n>>>>>>>>> Decryption result <<<<<<<<<<<:\n{0}", plainText);
			
			Console.ReadKey ();
		}
	}
}
