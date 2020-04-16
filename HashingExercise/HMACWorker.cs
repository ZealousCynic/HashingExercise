using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HashingExercise
{
    class HMACWorker
    {
        HMAC _hmac;
        public HMACWorker(HMAC hmac)
        {
            _hmac = hmac;
        }

        public bool CheckAuthenticity(byte[] msg, byte[] mac, byte[] key)
        {
            _hmac.Key = key;

            if (CompareByteArrays(_hmac.ComputeHash(msg), mac, MACByteLength()))
                return true;
            return false;
        }

        public byte[] ComputeMAC(byte[] msg, byte[] key)
        {
            _hmac.Key = key;
            return _hmac.ComputeHash(msg);
        }

        int MACByteLength()
        {
            return _hmac.HashSize / 8;
        }

        bool CompareByteArrays(byte[] a, byte[] b, int len)
        {
            for (int i = 0; i < len; i++)
                if (a[i] != b[i]) 
                    return false;
            return true;
        }
    }
}
