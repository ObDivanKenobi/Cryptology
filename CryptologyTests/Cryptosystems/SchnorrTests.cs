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
    public class SchnorrTests
    {
        [TestMethod()]
        public void HelpTest()
        {
            Trace.WriteLine(Schnorr.Help());
        }
    }
}