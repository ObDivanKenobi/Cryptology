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
            (int[] w, int[] x, int q, int r, string expectedResult)[] input = 
                {
                    ( w: new int[] { 2, 3, 7, 14, 29, 57 }, x: new int[] { 112, 199, 53, 70, 87 }, q: 120, r: 71, "СТЕНА"),
                    ( w: new int[] { 1, 2, 4, 9, 18, 35 }, x: new int[] { 42, 79, 78, 97, 154, 57 }, q: 80, r: 29, "БУЙВОЛ")
                };

            bool isOk = true;
            foreach(var e in input)
            {
                string result = MerkleHellman.Decrypt(e.x, e.w, e.q, e.r);
                isOk = result == e.expectedResult;
                if (!isOk)
                {
                    Debug.WriteLine($"Failed at: {e.expectedResult}");
                    break;
                }
            }

            Assert.IsTrue(isOk);
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