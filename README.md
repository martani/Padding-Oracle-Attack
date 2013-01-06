C# Padding Oracle Attack
=====================

A demonstration of a padding Oracle attack in `C#`.

Info & build
-----
The solution containing the projects `PaddingOracleAttackTest` and `PaddingOracleAttackLib` is developed under mono,
it should be easily used from Visual Studio also.

Usage
-----
You can use the class `PaddingOracleAttacker` from the library project `PaddingOracleAttackLib` in order to perform
padding oracle attacks.

This class accepts an Oracle object in the constructor. The Oracle should implement the interface `PaddingOracleAttackLib.ICBCOracle`.
The function `bool RequestOracle (byte[] cipher)` takes a byte array as cipher (usually 32 bytes IV+data) and 
returns `true` on a valid padding, `false` otherwise.

Take a look at `PaddingOracleAttackTest/Oracles` for two examples of such Oracles:
- `AES_CBCOracle`: implements a simple padding Oracle using AES as the cipher.
- `OnlineCBCOracle`: this is an online padding Oracle.

**Check `Main.cs` for how to use both of these.**
