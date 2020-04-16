using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HashingExercise
{
    class HMACTypeHandler
    {
        HMAC hmac;

        public HMACTypeHandler(HMACType _type)
        {
            switch(_type)
            {
                case HMACType.MD5:
                    hmac = new HMACMD5();
                    break;
                case HMACType.SHA1:
                    hmac = new HMACSHA1();
                    break;
                case HMACType.SHA2:
                    hmac = new HMACSHA256();
                    break;
                case HMACType.SHA3:
                    hmac = new HMACSHA384();
                    break;
                default:
                    break;
            }
        }

        public HMAC GetHMAC { get { return hmac; } }
    }
}
