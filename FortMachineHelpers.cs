/* Copyright (C) 2015-2017 Niko Rosvall <niko@cryptoextension.eu>*/

using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;

namespace FortMachine
{
    public static class FortMachineHelpers
    {

        public static string GetFileLastModified(string path)
        {
            return File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:ss");
        }

        //Function reads our magic header from the given file
        //and compares it to the constant. If they match function
        //returns true, otherwise it returns false
        public static bool IsFileEncrypted(string path)
        {
            byte[] header;

            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                using (BinaryReader reader = new BinaryReader(stream, Encoding.Default))
                {
                    //Read the header into the buffer
                    header = reader.ReadBytes(FortMachineConstants.MAGIC_HEADER_SIZE);
                }
            }

            return header.SequenceEqual(FortMachineConstants.MAGIC_HEADER);

        } //End method

        //Returns file size in megabytes.
        public static double GetFileSizeInMB(string path)
        {
            long size = GetFileSizeInBytes(path);

            return (size / 1024f) / 1024f;

        } //End method

        //Returns file size in bytes
        public static long GetFileSizeInBytes(string path)
        {
            FileInfo info = new FileInfo(path);
            long size = info.Length;
            
            return size;

        } //End method

        //Returns file count in the directory, does not process subdirectories
        public static int GetDirectoryFileCount(string path)
        {
            int count = 0;

            foreach(string file in Directory.GetFiles(path, "*", SearchOption.TopDirectoryOnly))
            {
                if (File.Exists(file))
                    count++;
            }

            return count;

        } //End method

        //Returns directory pointed by path file count recursively
        public static int GetDirectoryFileCountRecursive(string path)
        {
            int count = 0;

            foreach (string file in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
            {
                if (File.Exists(file))
                    count++;
            }

            return count;

        } //End method

        //Returns list of files in the directory. Does not include files in
        //possible subdirectories.
        public static List<string> GetFilesInDirectory(string path)
        {
            List<string> files = new List<string>();

            foreach(string file in Directory.GetFiles(path, "*", SearchOption.TopDirectoryOnly))
            {
                if(File.Exists(file))
                    files.Add(file);
            }

            return files;

        } //End method

        //Returns the list of files in the directory pointed by path and all the files in the subdirectories
        //of the path.
        public static List<string> GetFilesInDirectoryRecursive(string path)
        {
            List<string> files = new List<string>();

            foreach (string file in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
            {
                if (File.Exists(file))
                    files.Add(file);
            }

            return files;

        } //End method

        //Returns list of files which are encrypted. Parameter needs to be a list of files
        //with full paths.
        public static List<string> FindEncryptedFiles(List<string> ListOfFiles)
        {
            List<string> files = new List<string>();

            foreach(string file in ListOfFiles)
            {
                if (IsFileEncrypted(file))
                    files.Add(file);
            }

            return files;

        } //End method

        //Returns a list of files which are not encrypted with Fort.
        //Parameter needs to be a list of files
        //with full paths.
        public static List<string> FindPlainFiles(List<string> ListOfFiles)
        {
            List<string> files = new List<string>();

            foreach (string file in ListOfFiles)
            {
                if (!IsFileEncrypted(file))
                    files.Add(file);
            }

            return files;

        } //End method

    } //End class

} //End namespace
