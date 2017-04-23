/* Copyright (C) 2015-2017 Niko Rosvall <niko@cryptoextension.eu>*/

namespace FortMachine
{
    public static class FortMachineConstants
    {
        public static string ENCRYPTED_FILE_EXTENSION = ".fortenc";
        public static int IV_SIZE = 16; //128 bits
        public static int SALT_SIZE = 8; //64 bits
        public static int KEY_SIZE = 32; //256 bits
        public static int DATA_INTEGRITY_HASH_SIZE = 32; //256 bits
        public static byte[] MAGIC_HEADER = { 4, 6, 3, 9, 3, 3, 5, 2 };
        public static int MAGIC_HEADER_SIZE = 8; //64 bits

        public static uint RECOMMENDED_KEY_FILE_SIZE = 512; //4096 bits
    }
}
