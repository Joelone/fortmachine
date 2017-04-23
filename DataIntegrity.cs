/* Copyright (C) 2015-2017 Niko Rosvall <niko@cryptoextension.eu>*/

using System.IO;
using System.Security.Cryptography;

namespace FortMachine
{
    internal class DataIntegrity
    {
        //Compute and return new keyed hash from data.
        //Data is usually unencrypted because we want to verify
        //integrity of the original data, not encrypted one
        internal static byte[] GetHMACHash(byte[] data, byte[] key)
        {
            byte[] hash;

            using (HMACSHA256 hmac = new HMACSHA256(key))
                hash = hmac.ComputeHash(data);
            
            return hash;

        } //End method

        //Computer and return new keyed hash from stream.
        internal static byte[] GetHMACHash(Stream plain, byte[] key)
        {
            byte[] hash;

            using (HMACSHA256 hmac = new HMACSHA256(key))
                hash = hmac.ComputeHash(plain);

            return hash;

        } //End method

        //Generates new keyed hash from data and compares the generated hash
        //with the oldhash. Returns true if they match otherwise false.
        internal static bool VerifyHash(byte[] data, byte[] key, byte[] OldHash)
        {
            byte[] NewHash;
            int ret = 0;

            NewHash = GetHMACHash(data, key);

            if (OldHash.Length != NewHash.Length)
                return false;

            for(int i = 0; i < OldHash.Length; ++i)
            {
                ret |= (NewHash[i] ^ OldHash[i]);

                if (ret != 0)
                    return false;
            }

            return true;

        } //End method

        //Verify hash agaist new hash from stream
        internal static bool VerifyHash(Stream plain, byte[] key, byte[] OldHash)
        {
            byte[] NewHash;
            int ret = 0;

            NewHash = GetHMACHash(plain, key);

            if (OldHash.Length != NewHash.Length)
                return false;

            for (int i = 0; i < OldHash.Length; ++i)
            {
                ret |= (NewHash[i] ^ OldHash[i]);

                if (ret != 0)
                    return false;
            }

            return true;

        } //End method

    } //End class
} //End namespace
