using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cryptology;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace Cryptology.Tests
{
    [TestClass()]
    public class RSATests
    {
        [TestMethod()]
        public void DecryptTest()
        {
            int rb = 32015873,
                b = 174673,
                beta = 26803117,
                m1 = 18701373,
                expectedResult = 111890;

            int message = RSA.Decrypt(m1, beta, rb);

            Debug.WriteLine($"Expected: {expectedResult}\nActual: {message}");
            Assert.AreEqual(expectedResult, message);
        }
    }
}