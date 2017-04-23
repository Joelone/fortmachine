/* Copyright (C) 2015-2017 Niko Rosvall <niko@cryptoextension.eu>*/

using System;
using System.IO;
using System.Security.Cryptography;

namespace FortMachine
{
    public class FortKeyFile
    {
        private byte[] _data;
        private uint _length;
        private string _lastErrorMessage;

        public FortKeyFile(byte[] data, uint length)
        {
            this._data = data;
            this._length = length;
        }

        public static FortKeyFile LoadFromDisk(string path)
        {
            byte[] data;
            uint length;

            try
            {
                data = File.ReadAllBytes(path);
                length = (uint)data.Length;

                return new FortKeyFile(data, length);
            }
            catch
            {
                return null;
            }
        }

        internal byte[] Data
        {
            get { return this._data; }
        }

        internal string LastErrorMessage
        {
            get { return this._lastErrorMessage; }
        }

        internal uint Length
        {
            get { return this._length; }
        }

        internal bool Preserve(string path)
        {
            try
            {
                File.WriteAllBytes(path, this._data);

                return true;
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                this._lastErrorMessage = ex.Message;
                return false;
            }
        }

        public string GetPassphrasePresentationFromData()
        {
            byte[] byte_hash;
            string str_hash = "";
            SHA512 sha = new SHA512CryptoServiceProvider();

            byte_hash = sha.ComputeHash(this.Data);

            foreach (byte oneByte in byte_hash)
                str_hash += String.Format("{0:x2}", oneByte);

            return str_hash;
        }

        internal bool Validate(byte[] data)
        {
            if (data.Length != FortMachineConstants.RECOMMENDED_KEY_FILE_SIZE)
                return false;

            return true;
        }
    }
}
