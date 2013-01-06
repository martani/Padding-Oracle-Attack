/*
 * author: martani (martani.net@gmail.com)
 * copyright 2013
 * 
 */

using System;
using System.Net;
using PaddingOracleAttackLib;

namespace PaddingOracle.Oracles
{
	public class OnlineCBCOracle : ICBCOracle
	{
		//This Oracle is the test Oracle from the Crypto class on Coursera https://www.coursera.org/course/crypto
		//Use at your own responsibility!
		public bool RequestOracle(byte[] cipher)
		{
			const string BASE_URL = "http://crypto-class.appspot.com/po?er=";
            string urlData = Helpers.ConvertByteArrayToHexString(cipher);

            WebClient wc = new WebClient();

            try
            {
                wc.DownloadData(BASE_URL + urlData);
      		}
            catch (WebException e)
            {
                //Invalid padding
                if (e.Message.Contains("403"))
                    return false;

                //Valid padding, but wrong mac
                if (e.Message.Contains("404"))
                    return true;
            }
			
			//Failed, the oracle is not up!
            return false;
		}
	}
}

