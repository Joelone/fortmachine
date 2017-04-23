/* Copyright (C) 2015-2017 Niko Rosvall <niko@cryptoextension.eu>*/

namespace FortMachine
{
    public interface IEncryptionMachine
    {
        string EncryptedFileExtension { get; }
        bool Encrypt2(string passphrase, string inputpath, string outputpath, bool KeepPlainFile = false);
        bool Decrypt2(string passphrase, string inputpath, string outputpath);
        string GetLastErrorMessage();
        bool IsDataTampered { get; }
        byte[] Decrypt(byte[] cipher, byte[] key, byte[] IV);
        byte[] Encrypt(byte[] plain, byte[] key, byte[] IV);
        FortKey CreateKey(string passphrase);
        byte[] GetRandom16IV();
        byte[] GenerateRandomData(uint length);
        FortKeyFile GetNewKeyFile(uint length);
        bool PreserveKeyfile(FortKeyFile keyFile, string path);
        FortKeyFile LoadKeyfileFromDisk(string path);
    }
}
