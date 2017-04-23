/* Copyright (C) 2015-2017 Niko Rosvall <niko@cryptoextension.eu>*/

namespace FortMachine
{
    public class FortFactory
    {
        //Create new encryption machine and return it.
        //This is the only way to create an intance of the machine
        //from outside of this library.
        public IEncryptionMachine CreateEncryptionMachine()
        {
            IEncryptionMachine machine = new EncryptionMachine();
            return machine;
        }
    }
}
