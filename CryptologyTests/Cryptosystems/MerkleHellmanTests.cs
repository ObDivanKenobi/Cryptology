using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cryptology;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;
using System.Diagnostics;

namespace Cryptology.Tests
{
    [TestClass()]
    public class MerkleHellmanTests
    {
        [TestMethod()]
        public void TestSixBitChar()
        {
            SixBitRussianChar sbrc = new SixBitRussianChar('б');
            Debug.Write("Bits: [");
            foreach (var bit in sbrc.Bits)
                Debug.Write($"{bit} ");
            Debug.WriteLine("];");
        }

        [TestMethod()]
        public void TestSixBitChar_Consistency()
        {
            SixBitRussianChar fromChar = new SixBitRussianChar('С');
            byte[] bits = new byte[] { 0, 1, 1, 1, 1, 1 };
            SixBitRussianChar fromBits = new SixBitRussianChar(bits.Reverse().ToArray());
            bits = fromChar.Bits;
            Debug.Write("Bits from char: [");
            for(int i = 0; i < bits.Length; ++i)
                Debug.Write($"{bits[i]} ");
            Debug.WriteLine($"];\nChar: {fromChar.ToChar()}");

            bits = fromBits.Bits;
            Debug.Write("Bits from bits: [");
            for (int i = 0; i < bits.Length; ++i)
                Debug.Write($"{bits[i]} ");
            Debug.WriteLine($"];\nChar: {fromBits.ToChar()}");

            Assert.AreEqual(fromChar.ToChar(), fromBits.ToChar());
        }

        [TestMethod()]
        public void ToCharTest()
        {
            char ch = 'Ъ';
            SixBitRussianChar sbrc = new SixBitRussianChar(ch);
            char result = sbrc.ToChar();
            Debug.WriteLine($"Reconverted char: {result}.");

            Assert.AreEqual(ch, result);
        }

        [TestMethod()]
        public void DecryptTest()
        {
            //int[] w = { 2, 3, 7, 14, 29, 57 },
            //      x = { 112, 199, 53, 70, 87 };
            //int q = 120,
            //    r = 71;
            //string expectedResult = "СТЕНА";

            int[] w = { 1, 2, 4, 9, 18, 35 },
                  x = { 42, 79, 78, 97, 154, 57 };
            int q = 80,
                r = 29;

            string result = MerkleHellman.Decrypt(x, w, q, r);
            Debug.WriteLine($"Расшифрованное сообщение: {result}");

            //Assert.AreEqual(expectedResult, result);
        }

        [TestMethod()]
        public void EncryptTest()
        {
            string message = "СТЕНА";
            int[] w = { 2, 3, 7, 14, 29, 57 };
            int q = 120,
                r = 71;
            int[] expectedResult = {112, 199, 53, 70, 87 };

            int[] x = MerkleHellman.Encrypt(message, w, q, r);

            bool isOk = true;
            Debug.Write("x: [");
            for (int i = 0; i < x.Length; ++i)
            {
                Debug.Write($"{x[i]} ");
                isOk = x[i] == expectedResult[i];
            }
            Debug.WriteLine("]");

            Assert.IsTrue(isOk);
        }
    }
}