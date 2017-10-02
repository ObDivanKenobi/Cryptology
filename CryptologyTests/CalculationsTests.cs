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
    public class CalculationsTests
    {
        [TestMethod()]
        public void DiscreteLogarithmBruteforceTest()
        {
            //a^x = b mod m
            (int a, int b, int m, int correctResult)[] input = new[] { (2, 23, 35, 7),
                                                                       (54, 196, 596, 9),
                                                                       (270, 342, 503, 49)};

            foreach (var e in input)
                if (Calculations.DiscreteLogarithmBruteforce(e.a, e.b, e.m) != e.correctResult)
                    Assert.IsTrue(false);

            Assert.IsTrue(true);
        }

        [TestMethod()]
        public void DiscreteLogarithmShanksMethodTest()
        {
            //a^x = b mod m
            (int a, int b, int m, int correctResult)[] input = new[] { (2, 23, 35, 7),
                                                                       (54, 196, 596, 9),
                                                                       (270, 342, 503, 49)};

            foreach (var e in input)
                if (Calculations.DiscreteLogarithmShanksMethod(e.a, e.b, e.m) != e.correctResult)
                    Assert.IsTrue(false);

            Assert.IsTrue(true);
        }

        [TestMethod()]
        public void PowerComparisonBruteforceTest()
        {
            //x^a = b mod m
            (int a, int b, int m, int correctResult)[] input = new[] { (7, 23, 35, 2),
                                                                       (9, 196, 596, 54),
                                                                       (49, 342, 503, 270)};

            foreach (var e in input)
                if (Calculations.PowerComparisonBruteforce(e.a, e.b, e.m) != e.correctResult)
                    Assert.IsTrue(false);

            Assert.IsTrue(true);
        }

        [TestMethod()]
        public void IsPrimeTest()
        {
            (int input, bool correctResult)[] input = new[] { (1, false), (23, true),
                                                               (1543476, false), (1964323, true)};

            foreach (var e in input)
                if (Calculations.IsPrime(e.input) != e.correctResult)
                    Assert.IsTrue(false);

            Assert.IsTrue(true);
        }

        [TestMethod()]
        public void FactorizeTest()
        {
            int number = 111111111;
            var result = Calculations.Factorize(number);

            StringBuilder output = new StringBuilder($"{number} =");
            foreach (var a in result)
            {
                output.Append($" {a.Key}");
                if (a.Value != 1)
                    output.Append($"^{a.Value}");
            }

            Debug.WriteLine(output.ToString());

            Assert.IsTrue(true);
        }

        [TestMethod()]
        public void EulersTotientFunctionTest()
        {
            (int input, int correctResult)[] input = new[] { (1, 1), (23, 22),
                                                               (1543476, 467280), (61242, 19952)};

            foreach (var e in input)
                if (Calculations.EulersTotientFunction(e.input) != e.correctResult)
                    Assert.IsTrue(false);

            Assert.IsTrue(true);
        }

        [TestMethod()]
        public void IsPrimitiveElementTest()
        {
            (int number, int module)[] input = new[] { (1, 2), (7, 29), (18, 29),
                                                       (435, 787), (436, 787),
                                                       (2822, 3853), (3675, 3853), (398983, 860941), (398991, 860941)};

            foreach (var e in input)
            {
                var primitiveElements = Calculations.FindPrimitiveElements(e.module);
                bool contains = primitiveElements.Contains(e.number),
                     isPrimitive = Calculations.IsPrimitiveElement(e.number, e.module);

                //bedug
                /*
                if (contains != isPrimitive)
                {
                    StringBuilder trace = new StringBuilder();
                    trace.Append('-', 60);
                    trace.AppendLine();
                    foreach (var entry in primitiveElements)
                        trace.Append($" {entry}");
                    trace.AppendLine();
                    trace.Append($"{(contains ? "contains" : "does no contain")} {e.number} but it {(isPrimitive ? "is" : "isn't")} primitive");

                    Debug.WriteLine(trace);
                }
                */

                Assert.AreEqual(contains, isPrimitive);
            }
        }

        [TestMethod()]
        public void FindPrimitiveElementsTest()
        {
            (int module, int correctQuantity)[] input = new[] { (2, Calculations.EulersTotientFunction(2-1)),
                                                                (13, Calculations.EulersTotientFunction(13-1)),
                                                                (29, Calculations.EulersTotientFunction(29-1)),
                                                                (47, Calculations.EulersTotientFunction(47-1)),
                                                                (787, Calculations.EulersTotientFunction(787-1)),
                                                                (3853, Calculations.EulersTotientFunction(3853-1)),
                                                                (9973, Calculations.EulersTotientFunction(9973-1)),
                                                                (860941, Calculations.EulersTotientFunction(860941-1))};
            //debug
            //bool isOk = true;

            foreach(var e in input)
            {
                StringBuilder output = new StringBuilder($"{e.module}:");
                var foundElements = Calculations.FindPrimitiveElements(e.module);
                bool isCurrentOk = foundElements.Count == e.correctQuantity;
                //debug
                //isOk &= isCurrentOk;

                //foreach (var element in foundElements)
                //    output.Append($" {element}");
                //if (!isCurrentOk)
                //    output.Append($" failed — quantity of found elements ({foundElements.Count}) != correct quantity ({e.correctQuantity}).");

                Assert.IsTrue(isCurrentOk);
                Debug.WriteLine(output.ToString());
            }
        }
    }
}