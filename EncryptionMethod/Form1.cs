using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EncryptionMethod
{
    public partial class Form1 : Form
    {
        private const string SUBCYPHER1 = "DEFGHIJKLMNOPQRSTUVWXYZABC";
        private const string SUBCYPHER2 = "GHIJKLMNOPQRSTUVWXYZABCDEF";
        private const string SUBCYPHER3 = "JKLMNOPQRSTUVWXYZABCDEFGHI";
        private const string SUBCYPHER4 = "MNOPQRSTUVWXYZABCDEFGHIJKL";

        private const string KEY_DESCRIPTION = "1->4, 2->8, 3->1, 4->5, 5->7, 6->2, 7->6, 8->3";
        private static readonly int[] KEY = new int[] { 4, 8, 1, 5, 7, 2, 6, 3};
        public Form1()
        {
            InitializeComponent();
            
            txbKey2.Text = KEY_DESCRIPTION;
        }

        #region Phương pháp thay thế (Substitution)
        //==================== Phương pháp thay thế (Substitution) ========================//

        private string Substitution(string plaintext)
        {
            plaintext = plaintext.ToUpper();
            int index;
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < plaintext.Length; i++)
            {
                index = (int)plaintext[i] - 65;
                switch (i % 4)
                {
                    case 0:
                        builder.Append(SUBCYPHER1[index]);
                        break;
                    case 1:
                        builder.Append(SUBCYPHER2[index]);
                        break;
                    case 2:
                        builder.Append(SUBCYPHER3[index]);
                        break;
                    case 3:
                        builder.Append(SUBCYPHER4[index]);
                        break;
                }
            }
            return builder.ToString();
        }

        private void txbPlaintext_TextChanged(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(txbPlaintext1.Text))
            {
                return;
            }

            if (!Regex.IsMatch(txbPlaintext1.Text, @"^[a-zA-Z]+$"))
            {
                txbPlaintext1.Clear();
                txbCiphertext1.Clear();
                MessageBox.Show("Bạn chỉ được nhập ký tự chữ cái (hoa hoặc thường) không dấu!\n\n" +
                    "Chú ý: Hãy đảm bảo bạn đã tắt Unikey trước khi nhập!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            txbCiphertext1.Text = Substitution(txbPlaintext1.Text);
        }
        #endregion


        #region Phương pháp hoán vị (Permutation)
        //==================== Phương pháp thay thế (Permutation) ========================//

        // Thêm khoảng trắng cho đủ khối 8 ký tự
        private string AddSpace(string text)
        {
            int length = text.Length;
            if (length % 8 == 0)
            {
                return text;
            }

            int numSpace = 8 - length % 8;
            StringBuilder builder = new StringBuilder(text);
            for (int i = 0; i < numSpace; i++)
            {
                builder.Append(" ");
            }
            return builder.ToString();
        }

        private string Permutation(string plaintext)
        {
            plaintext = AddSpace(plaintext);
            int length = plaintext.Length;
            char[] cyphertext = new char[length];

            int block;
            int letterLocation;
            for (int i = 0; i < length; i++)
            {
                block = i / 8 + 1;
                letterLocation = 8 - (i % 8);
                cyphertext[block * 8 - KEY[letterLocation - 1]] = plaintext[i];
            }

            return new string(cyphertext);
        }

        private void txbPlaintext2_TextChanged(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(txbPlaintext2.Text))
            {
                return;
            }

            if (!Regex.IsMatch(txbPlaintext2.Text, @"^[a-zA-Z]+$"))
            {
                txbPlaintext2.Clear();
                txbCyphertext2.Clear();
                MessageBox.Show("Bạn chỉ được nhập ký tự chữ cái (hoa hoặc thường) không dấu!\n\n" +
                    "Chú ý: Hãy đảm bảo bạn đã tắt Unikey trước khi nhập!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            txbCyphertext2.Text = Permutation(txbPlaintext2.Text);
        }

        #endregion


        #region Phương pháp XOR
        //==================== Phương pháp XOR ========================//
        private string PrintBits(BitArray bits)
        {
            StringBuilder builder = new StringBuilder();
            StringBuilder tmp = new StringBuilder();
            int block = bits.Length / 8;

            for (int i = 1; i <= block; i++)
            {
                for (int j = 8 * i - 1; j >= 8 * i - 8; j--)
                {
                    tmp.Append(bits[j].GetHashCode());
                }
                builder.Append(tmp.ToString()).Append(" ");

                tmp.Clear();
            }

            return builder.ToString();
        }

        private string XORToBinary(string plaintext, string key)
        {
            int pLength = plaintext.Length;
            int kLength = key.Length;

            byte[] pArray = new byte[pLength];
            byte[] kArray = new byte[kLength];

            for (int i = 0; i < pLength; i++)
            {
                pArray[i] = (byte)plaintext[i];
            }

            for (int i = 0; i < kLength; i++)
            {
                kArray[i] = (byte)key[i];
            }

            BitArray pBits = new BitArray(pArray);
            BitArray kBits = new BitArray(kArray);
            pBits.Xor(kBits);

            return PrintBits(pBits);
        }

        private string XORToDecimal(string plaintext, string key)
        {
            int pLength = plaintext.Length;
            int kLength = key.Length;

            int[] pArray = new int[pLength];
            int[] kArray = new int[kLength];

            for (int i = 0; i < pLength; i++)
            {
                pArray[i] = (int)plaintext[i];
            }

            for (int i = 0; i < kLength; i++)
            {
                kArray[i] = (int)key[i];
            }

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < pLength; i++)
            {
                builder.Append(string.Format("{0} ", pArray[i] ^ kArray[i]));
            }

            return builder.ToString();
        }

        private void txbPlaintext3_TextChanged(object sender, EventArgs e)
        {
            txbLenghtPlaintext3.Text = txbPlaintext3.Text.Length.ToString();
        }

        private void txbKey3_TextChanged(object sender, EventArgs e)
        {
            txbLengthKey3 .Text = txbKey3.Text.Length.ToString();
        }

        private void btnEncrytion3_Click(object sender, EventArgs e)
        {
            // Quy các chữ cái về dạng in hoa
            txbPlaintext3.Text = txbPlaintext3.Text.ToUpper();
            txbKey3.Text = txbKey3.Text.ToUpper();

            string plaintext = txbPlaintext3.Text;
            string key = txbKey3.Text;

            if (string.IsNullOrEmpty(plaintext))
            {
                MessageBox.Show("Bản rõ không được để trống!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (string.IsNullOrEmpty(key))
            {
                MessageBox.Show("Khóa không được để trống!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (!Regex.IsMatch(plaintext, @"^[A-Z]+$") || !Regex.IsMatch(key, @"^[A-Z]+$"))
            {
                MessageBox.Show("Bạn chỉ được nhập ký tự chữ cái (hoa hoặc thường) không dấu!\n\n" +
                    "Chú ý: Hãy đảm bảo bạn đã tắt Unikey trước khi nhập!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (plaintext.Length != key.Length)
            {
                MessageBox.Show("Bản rõ và khóa phải có cùng số ký tự!\n" +
                    "Ví dụ: 'CAT' và 'VVV'", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            txbCipher3.Text = XORToBinary(txbPlaintext3.Text, txbKey3.Text);
            txbDecimal3.Text = XORToDecimal(txbPlaintext3.Text, txbKey3.Text);
        }

        #endregion


        #region Phương pháp Vernam
        //==================== Phương pháp Vernam ========================//

        private string Verman(string plaintext, string oneTimePad)
        {
            int length = plaintext.Length;
            int pos1, pos2;

            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < length; i++)
            {
                // Cách 1:
                pos1 = plaintext[i] - 64;
                pos2 = oneTimePad[i] - 64;
                builder.Append((char)((pos1 + pos2) % 26 + 64));

                // Cách 2:
                //builder.Append((char)((plaintext[i] + oneTimePad[i] - 128) % 26 + 64));
            }

            return builder.ToString();
        }

        private void txbPlaintext4_TextChanged(object sender, EventArgs e)
        {
            txbLengthPlaintext4.Text = txbPlaintext4.Text.Length.ToString();
        }

        private void txbOneTimePad4_TextChanged(object sender, EventArgs e)
        {
            txbLengthOTP4.Text = txbOneTimePad4.Text.Length.ToString();
        }

        private void btnEncryption4_Click(object sender, EventArgs e)
        {
            // Quy các chữ cái về dạng in hoa
            txbPlaintext4.Text = txbPlaintext4.Text.ToUpper();
            txbOneTimePad4.Text = txbOneTimePad4.Text.ToUpper();

            string plaintext = txbPlaintext4.Text;
            string oneTimePad = txbOneTimePad4.Text;

            if (string.IsNullOrEmpty(plaintext))
            {
                MessageBox.Show("Bản rõ không được để trống!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (string.IsNullOrEmpty(oneTimePad))
            {
                MessageBox.Show("Tập nối thêm không được để trống!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (!Regex.IsMatch(plaintext, @"^[A-Z]+$") || !Regex.IsMatch(oneTimePad, @"^[A-Z]+$"))
            {
                MessageBox.Show("Bạn chỉ được nhập ký tự chữ cái (hoa hoặc thường) không dấu!\n\n" +
                    "Chú ý: Hãy đảm bảo bạn đã tắt Unikey trước khi nhập!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (plaintext.Length != oneTimePad.Length)
            {
                MessageBox.Show("Bản rõ và tập nối thêm phải có cùng số ký tự!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            txbCyphertext4.Text = Verman(plaintext, oneTimePad);
        }

        #endregion

        
    }

}
