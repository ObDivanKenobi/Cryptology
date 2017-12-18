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
    public class NoKeyTransmissionTests
    {
        [TestMethod()]
        public void DecryptBruteforceTest()
        {
            (int m1, int m2, int m3, int p, int expected)[] input =
            {
                (m1: 11039, m2: 31214, m3: 14790, p: 49559, expected: 45710)
            };
            bool isOk = true;

            foreach(var e in input)
            {
                int m = NoKeyTransmission.DecryptBruteforce(e.p, e.m1, e.m2, e.m3);
                isOk = m == e.expected;
                if(!isOk)
                {
                    Debug.WriteLine($"Failed at {m} (ожидалось {e.expected})");
                    break;
                }
            }

            Assert.IsTrue(isOk);
        }

        [TestMethod()]
        public void DecryptShanksTest()
        {
            (int m1, int m2, int m3, int p, int expected)[] input =
            {
                (m1: 11039, m2: 31214, m3: 14790, p: 49559, expected: 45710)
            };
            bool isOk = true;

            foreach (var e in input)
            {
                int m = NoKeyTransmission.DecryptShanks(e.p, e.m1, e.m2, e.m3);
                isOk = m == e.expected;
                if (!isOk)
                {
                    Debug.WriteLine($"Failed at {m} (ожидалось {e.expected})");
                    break;
                }
            }

            Assert.IsTrue(isOk);
        }
    }
}