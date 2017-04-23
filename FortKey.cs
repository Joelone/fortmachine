/* Copyright (C) 2015-2017 Niko Rosvall <niko@cryptoextension.eu>*/

using System.Linq;
using System.Security.Cryptography;

namespace FortMachine
{
    public class FortKey
    {
        private string _passphrase;

        //Iteration count for Rfc2898DeriveBytes
        private const int ITERATIONS = 10000;

        //Holds the salt created after GetNew() is called.
        private byte[] _salt;

        public FortKey(string passphrase)
        {
            this._passphrase = passphrase;

        } //End constructor

        //This is available when GetNew() is called to create a new key.
        //Otherwise returns null.
        public byte[] Salt
        {
            get { return this._salt; }

        } //End property

        //Get new key buffer using existing salt
        public byte[] GetNew(byte[] salt)
        {
            byte[] key = new byte[FortMachineConstants.KEY_SIZE];

            Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(this._passphrase, salt, ITERATIONS);
            key = bytes.GetBytes(FortMachineConstants.KEY_SIZE);
            bytes.Reset();

            return key;

        } //End method

        //Get new key buffer. This method also creates random salt
        //and stores it to _salt property for later use.
        public byte[] GetNew()
        {
            byte[] salt = new byte[FortMachineConstants.SALT_SIZE];
            byte[] key = new byte[FortMachineConstants.KEY_SIZE];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                rng.GetBytes(salt);

            this._salt = salt;

            Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(this._passphrase, salt, ITERATIONS);
            key = bytes.GetBytes(FortMachineConstants.KEY_SIZE);
            bytes.Reset();

            return key;

        } //End method

        //Verify a passphrase.
        public static bool VerifyPassphrase(string passphrase, byte[] salt, byte[] key)
        {
            bool success = false;

            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(passphrase, salt, ITERATIONS))
            {
                success = bytes.GetBytes(FortMachineConstants.KEY_SIZE).SequenceEqual(key);
            }

            return success;

        } //End method

    } //End class

} //End namespace
