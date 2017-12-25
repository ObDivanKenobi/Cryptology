using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cryptology;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Numerics;

namespace Cryptology.Tests
{
    [TestClass()]
    public class SchnorrTests
    {
        [TestMethod()]
        public void HelpTest()
        {
            Trace.WriteLine(Schnorr.Help());
        }

        [TestMethod()]
        public void CheckTest()
        {
            int r = 32607,
                g = 2902,
                y = 9107,
                p = 33107;

            (int e, int s)[] input = new[] { (15776, 9856), (490, 8108), (9987, 7309), (155, 1267) };

            for (int i = 0; i < input.Length; ++i)
            {
                Trace.WriteLine($"e = {input[i].e}, s = {input[i].s}, result = {Schnorr.Check(g, input[i].s, y, input[i].e, p, r)}");
            }
        }

        [TestMethod()]
        public void AttackTest()
        {
            (int p, int q, int g, int y, int key)[] input = new[]
            {
                (p: 48731, q: 443, g: 11444, y: 7355, key: 357)
            };

            foreach (var e in input)
            {
                int calculatedKey = Schnorr.Attack(e.p, e.g, e.y);
                if (calculatedKey != e.key)
                {
                    Debug.WriteLine($"failed at (p: {e.p}, g: {e.g}, y: {e.y}, key: {e.key}) with calculated key {calculatedKey}.");
                    Assert.IsFalse(true);
                }
            }
        }
    }
}