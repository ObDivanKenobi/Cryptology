using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cryptology.Cryptosystems;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace Cryptology.Cryptosystems.Tests
{
    [TestClass()]
    public class ElGamalTests
    {
        [TestMethod()]
        public void DecodeTest()
        {
            (int Q, (int p, int g, int y) openKey, int k, (int a, int b) expectedResult)[] input =
            {
                (Q: 15309, openKey: (p: 25679, g: 10025, y: 19120), k: 16780, expectedResult: (a: 11875, b: 16196))
            };
            bool isOk = true;

            foreach (var e in input)
            {
                var result = ElGamal.Encrypt(e.Q, e.openKey, e.k);
                isOk = result.a == e.expectedResult.a && result.b == e.expectedResult.b;
                if (!isOk)
                {
                    Debug.WriteLine($"Failed at {e.Q} with ({result.a},{result.b}) != ({e.expectedResult.a},{e.expectedResult.b})");
                    break;
                }
            }

            Assert.IsTrue(isOk);
        }

        [TestMethod()]
        public void CalculateSecretKeyBruteforceTest()
        {
            ((int p, int g, int y) openKey, int expected)[] input =
            {
                (openKey: (p: 25679, g: 10025, y: 19120), expected: 14678)
            };
            bool isOk = true;

            foreach (var e in input)
            {
                int x = ElGamal.CalculateSecretKeyBruteforce(e.openKey);
                isOk = x == e.expected;
                if (!isOk)
                {
                    Debug.WriteLine($"Failed at x {x} != {e.expected}");
                }
            }

            Assert.IsTrue(isOk);
        }

        [TestMethod()]
        public void DecryptTest()
        {
            int p = 54751,
                Q1 = 123,
                b1 = 50973,
                b2 = 4246,
                expected = 4905;

            int result = ElGamal.Decrypt(b1, b2, Q1, p);

            Assert.AreEqual(expected, result);
        }
    }
}