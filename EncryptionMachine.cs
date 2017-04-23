/* Copyright (C) 2015-2017 Niko Rosvall <niko@cryptoextension.eu>*/

using System.IO;
using System.Security.Cryptography;
using System;

namespace FortMachine
{
    internal class EncryptionMachine : IEncryptionMachine
    {
        private string _LastErrorMessage;
        private bool _IsDataTampered;

        //Implements IEncryptionMachine.Encrypt
        //Main user interface for the FortMachine library.
        //Encrypt plain bytes and returns encrypted byte array
        public byte[] Encrypt(byte[] plain, byte[] key, byte[] IV)
        {
            byte[] cipher;
            byte[] data;

            data = plain;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream stream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                    }

                    cipher = stream.ToArray();
                }
            }

            return cipher;

        } //End Method

        //Implements IEncryptionMachine.Decrypt
        //Main user interface for the FortMachine library.
        //Decrypt bytes and returns plain byte array.
        public byte[] Decrypt(byte[] cipher, byte[] key, byte[] IV)
        {
            MemoryStream streamPlain;
            byte[] plain;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream stream = new MemoryStream(cipher))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                    {
                        streamPlain = new MemoryStream();
                        cryptoStream.CopyTo(streamPlain);
                    }
                }
            }

            plain = streamPlain.ToArray();
            streamPlain.Close();

            return plain;

        } //End method

        //Implements IEncryptionMachine.CreateKey
        //Main user interface for the FortMachine library.
        //Returns new instance of FortKey
        public FortKey CreateKey(string passphrase)
        {
            FortKey key = new FortKey(passphrase);

            return key;

        } //End method

        //Create key using existing salt. This is used on decryption.
        //For encryption, call CreateKey.
        //Returns the key as a byte array.
        private byte[] ProcessKeyWithSalt(string passphrase, byte[] salt)
        {
            byte[] hash;
            FortKey key = new FortKey(passphrase);

            hash = key.GetNew(salt);
            
            return hash;

        } // End method

        //Implements IEncryptionMachine.GetRandom16IV
        //Main user interface for the FortMachine library.
        //Returns new random 128 initialization vector
        public byte[] GetRandom16IV()
        {
            RNGCryptoServiceProvider rng;
            byte[] bytes = new byte[FortMachineConstants.IV_SIZE];

            rng = new RNGCryptoServiceProvider();
            rng.GetBytes(bytes);

            return bytes;

        } //End method

        //Implements IEncryptionMachine.EncryptedFileExtension
        //Main user interface for the FortMachine library.
        public string EncryptedFileExtension
        {
            get { return FortMachineConstants.ENCRYPTED_FILE_EXTENSION; }

        } //End method

        //Implements IEncryptionMachine.IsDataTampered
        //Main user interface for the FortMachine library.
        public bool IsDataTampered
        {
            get { return this._IsDataTampered; }

        } //End property

        //Implements IEncryptionMachine.GetLastErrorMessage
        //Main user interface for the FortMachine library.
        public string GetLastErrorMessage()
        {
            return this._LastErrorMessage;

        } //End method

        //Implements IEncryptionMachine.Encrypt2
        //Main user interface for the FortMachine library.
        //This method can be used to encrypt big files as stream based operations are used and
        //data is not read into memory at once.
        public bool Encrypt2(string passphrase, string inputpath, string outputpath, bool KeepPlainFile = false)
        {
            FileStream StreamIn = null;
            FileStream StreamOut = null;
            CryptoStream crypto = null;

            try
            {
                byte[] IV;
                FortKey key;
                byte[] KeyBytes;
                int BufferSize = 4096;
                byte[] buffer = new byte[BufferSize];
                int BytesRead;
                byte[] IntegrityHash;

                key = this.CreateKey(passphrase);
                KeyBytes = key.GetNew();
                IV = this.GetRandom16IV();

                StreamIn = new FileStream(inputpath, FileMode.Open, FileAccess.Read);
                StreamOut = new FileStream(outputpath, FileMode.OpenOrCreate, FileAccess.Write);

                IntegrityHash = DataIntegrity.GetHMACHash(StreamIn, KeyBytes);
                StreamIn.Seek(0, SeekOrigin.Begin);

                //First write our magic header to mark that the file is encrypted with Fort
                StreamOut.Write(FortMachineConstants.MAGIC_HEADER, 0, FortMachineConstants.MAGIC_HEADER_SIZE);
                //Then, write IV into the file
                StreamOut.Write(IV, 0, FortMachineConstants.IV_SIZE);
                //Then, write the salt into the file
                StreamOut.Write(key.Salt, 0, FortMachineConstants.SALT_SIZE);
                //Then, write the integrity has into the file
                StreamOut.Write(IntegrityHash, 0, FortMachineConstants.DATA_INTEGRITY_HASH_SIZE);

                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

                aes.Key = KeyBytes;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;

                crypto = new CryptoStream(StreamOut, aes.CreateEncryptor(), CryptoStreamMode.Write);

                do
                {
                    BytesRead = StreamIn.Read(buffer, 0, BufferSize);
                    crypto.Write(buffer, 0, BytesRead);

                } while (BytesRead != 0);

                crypto.Close();
                StreamIn.Close();

                if (!KeepPlainFile)
                    File.Delete(inputpath);            
            }
            catch(Exception ex)
            {
                if (crypto != null)
                    crypto.Close();

                if (StreamIn != null)
                    StreamIn.Close();

                if (File.Exists(outputpath))
                    File.Delete(outputpath);

                this._LastErrorMessage = "Encryption failed: " + ex.Message;
                return false;
            }

            return true;

        } //End method

        //Implements IEncryptionMachine.Decrypt2
        //Main user interface for the FortMachine library.
        //This method can be used to decrypt big files as it uses stream based operation for reading and 
        //writing the data.
        //Returns true on success, false on failure.
        public bool Decrypt2(string passphrase, string inputpath, string outputpath)
        {
            FileStream StreamIn = null;
            FileStream StreamOut = null;
            CryptoStream decrypto = null;
            FileStream NewPlainStream = null;

            //Make sure our outputpath has correct encoding
            //byte[] filenamebytes = Encoding.Default.GetBytes(outputpath);
            //outputpath = Encoding.Default.GetString(filenamebytes);

            try
            {
                byte[] key;
                byte[] IV;
                byte[] salt;
                byte[] magic_header;
                int BufferSize = 4096;
                byte[] buffer = new byte[BufferSize];
                int BytesRead;
                byte[] IntegrityHash;

                IV = new byte[FortMachineConstants.IV_SIZE];
                salt = new byte[FortMachineConstants.SALT_SIZE];
                magic_header = new byte[FortMachineConstants.MAGIC_HEADER_SIZE];
                IntegrityHash = new byte[FortMachineConstants.DATA_INTEGRITY_HASH_SIZE];

                StreamIn = new FileStream(inputpath, FileMode.Open, FileAccess.ReadWrite);
                StreamOut = new FileStream(outputpath, FileMode.OpenOrCreate, FileAccess.Write);

                //Ignore the magic header and move file pointer to the next bytes
                StreamIn.Read(magic_header, 0, FortMachineConstants.MAGIC_HEADER_SIZE);
                //Read the IV into the buffer
                StreamIn.Read(IV, 0, FortMachineConstants.IV_SIZE);
                //Read passphrase salt into a buffer
                StreamIn.Read(salt, 0, FortMachineConstants.SALT_SIZE);
                //Read data integrity hash
                StreamIn.Read(IntegrityHash, 0, FortMachineConstants.DATA_INTEGRITY_HASH_SIZE);

                key = this.ProcessKeyWithSalt(passphrase, salt);

                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

                aes.Key = key;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;

                decrypto = new CryptoStream(StreamOut, aes.CreateDecryptor(), CryptoStreamMode.Write);

                do
                {
                    BytesRead = StreamIn.Read(buffer, 0, BufferSize);
                    decrypto.Write(buffer, 0, BytesRead);

                } while (BytesRead != 0);

                decrypto.Close();
                StreamIn.Close();

                //Create new temporary stream from the decrypted file to verify data integrity
                NewPlainStream = new FileStream(outputpath, FileMode.Open, FileAccess.Read);

                //Verify data integrity
                if (!DataIntegrity.VerifyHash(NewPlainStream, key, IntegrityHash))
                {
                    this._IsDataTampered = true;
                }
                else
                {
                    this._IsDataTampered = false;
                }

                NewPlainStream.Close();

                File.Delete(inputpath);
            }
            catch (Exception ex)
            {
                //Clean up streams, if they where created
                if(decrypto != null)
                    decrypto.Close();

                if (StreamOut != null)
                    StreamOut.Close();

                if(StreamIn != null)
                    StreamIn.Close();

                if (NewPlainStream != null)
                    NewPlainStream.Close();

                //As decryption failed, check if the output file was created and delete it
                //because it would be incomplete.
               
                if (File.Exists(outputpath))
                    File.Delete(outputpath);

                this._LastErrorMessage = "Decryption failed: " + ex.Message;

                return false;
            }

            return true;

        } //End method

        //Implements IEncryptionMachine.GenerateRandomData
        //Generates cryptographically random data up to length.
        public byte[] GenerateRandomData(uint length)
        {
            RNGCryptoServiceProvider rng;
            byte[] bytes = new byte[length];

            rng = new RNGCryptoServiceProvider();
            rng.GetBytes(bytes);

            return bytes;
        }

        //Implements IEncryptionMachine.GetNewKeyFile
        //Returns new instance of FortKeyFile
        public FortKeyFile GetNewKeyFile(uint length)
        {
            FortKeyFile kfile;
            byte[] data;

            data = this.GenerateRandomData(length);

            kfile = new FortKeyFile(data, length);

            return kfile;
        }

        //Implements IEncryptionMachine.PreserveKeyfile
        //Returns true on success, false on failure. On failure sets LastErrorMessage
        public bool PreserveKeyfile(FortKeyFile keyFile, string path)
        {
            if(!keyFile.Preserve(path))
            {
                this._LastErrorMessage = keyFile.LastErrorMessage;
                return false;
            }

            return true;
        }

        //Implements IEncryptionMachine.LoadKeyfileFromDisk
        //On failure, returns null and sets the LastErrorMessage
        public FortKeyFile LoadKeyfileFromDisk(string path)
        {
            FortKeyFile keyFile;

            keyFile = FortKeyFile.LoadFromDisk(path);

            if(keyFile == null)
            {
                this._LastErrorMessage = "Unable to read the key file from disk.";
                return null;
            }

            if(!keyFile.Validate(keyFile.Data))
            {
                this._LastErrorMessage = "Invalid keyfile data.";
                return null;
            }

            return keyFile;
        }

    } //End class

} //End namespace
