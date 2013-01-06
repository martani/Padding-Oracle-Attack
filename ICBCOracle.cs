/*
 * author: martani (martani.net@gmail.com)
 * copyright 2013
 * 
 */

using System;

namespace PaddingOracle.Oracles
{
	/// <summary>
	/// Represents a CBC oracle, a one even Socrates should trust its answers.
	/// </summary>
	public interface ICBCOracle
	{
		/// <summary>
		/// Requests the oracle.
		/// </summary>
		/// <returns>
		/// True if after decryption the PKCS #7 padding is correct, false otherwise.
		/// </returns>
		/// <param name='cipher'>
		/// A 32 bytes block (2 AES blocks) in which the first block is IV,
		/// the second is the encrypted data itself.
		/// </param>
		bool RequestOracle(byte[] cipher);
	}
}

