using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace HashingExercise
{
    class HashingViewModel : INotifyPropertyChanged
    {
        Dictionary<HMACType, string> selectableHashTypes = new Dictionary<HMACType, string>()
        {
            { HMACType.MD5, "MD5" },
            { HMACType.SHA1, "SHA1" },
            { HMACType.SHA2, "SHA2" },
            { HMACType.SHA3, "SHA3" }
        };

        #region FIELDS

        string key = "KEYTEST";
        string plainText = "PLAINTEXTTEST";
        string verifiedASCII;
        string verifiedHEX;
        bool hmacSuccess;
        int dumbSolution = 0;
        HMACType selectedType;
        ICommand computeMACCommand;
        ICommand verifyMACCommand;
        HMACTypeHandler handler;
        HMACWorker worker;

        #endregion

        #region PROPERTIES

        public Dictionary<HMACType, string> SelectableHashTypes { get { return selectableHashTypes; } }
        public HMACType SelectedType
        {
            get { return selectedType; }
            set
            {
                selectedType = value;
                OnPropertyChanged("SelectedType");
            }
        }

        public string VerifiedASCII
        {
            get { return verifiedASCII; }
            set
            {
                verifiedASCII = value;
                OnPropertyChanged("VerifiedASCII");
            }
        }

        public string VerifiedHEX
        {
            get { return verifiedHEX; }
            set
            {
                verifiedHEX = value;
                OnPropertyChanged("VerifiedHEX");
            }
        }

        public string Key
        {
            get { return key; }
            set
            {
                key = value;
                OnPropertyChanged("Key");
            }
        }

        public string PlainText
        {
            get { return plainText; }
            set
            {
                plainText = value;
                OnPropertyChanged("PlainText");
            }
        }

        public bool HMACSuccess { get { return hmacSuccess; } set
            {
                hmacSuccess = value;
                OnPropertyChanged("HMACSuccess");
            } }

        public int DumbSolution { get { return dumbSolution; } set
            {
                dumbSolution = value;
                OnPropertyChanged("DumbSolution");
            } }
        #endregion


        #region PROPERTIES, COMMANDS
        public ICommand ComputeMACCommand { get { return computeMACCommand; } }
        public ICommand VerifyMACCommand { get { return verifyMACCommand; } }

        #endregion


        public event PropertyChangedEventHandler PropertyChanged;

        public HashingViewModel()
        {
            computeMACCommand = new DelegateCommand(ComputeHMAC);
            verifyMACCommand = new DelegateCommand(VerifyMAC);
        }

        protected void OnPropertyChanged([CallerMemberName] string propName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
        }

        void ComputeHMAC(object o)
        {
            DumbSolution = 0;

            handler = new HMACTypeHandler(SelectedType);

            worker = new HMACWorker(handler.GetHMAC);

            byte[] data = Encoding.ASCII.GetBytes(PlainText);
            byte[] key = Encoding.ASCII.GetBytes(Key);

            byte[] returned = worker.ComputeMAC(data, key);

            VerifiedASCII = Convert.ToBase64String(returned);

            StringBuilder sb = new StringBuilder(returned.Length * 2);

            for (int i = 0; i < returned.Length; i++)
                sb.AppendFormat("{0:X2}", returned[i]);

            VerifiedHEX = sb.ToString();
        }


        void VerifyMAC(object o)
        {
            if (worker == null)
                return;

            byte[] data = Encoding.ASCII.GetBytes(PlainText);
            byte[] mac = Convert.FromBase64String(VerifiedASCII);
            byte[] key = Encoding.ASCII.GetBytes(Key);

            HMACSuccess = worker.CheckAuthenticity(data, mac, key);

            DumbSolution = 100;
        }

        //Call to test with local params rather than properties
        void DebugVerify(byte[] data, byte[] mac, byte[] key)
        {
            HMACSuccess = worker.CheckAuthenticity(data, mac, key);
            DumbSolution = 100;
        }
    }
}
