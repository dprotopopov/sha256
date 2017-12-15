using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace sha256.Tests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            var message = Encoding.Default.GetBytes("The quick brown fox jumps over the lazy dog");
            var digit = new Sha256.Sha256Digest().Hash(message);
            Assert.AreEqual("D7A8FBB3 07D78094 69CA9ABC B0082E4F 8D5651E4 6D3CDB76 2D02D0BF 37C9E592", digit.ToHex());
        }
        [TestMethod]
        public void TestMethod2()
        {
            Console.WriteLine(Sha256.Sha256Digest.Rotr);
            Console.WriteLine(Sha256.Sha256Digest.E0);
            Console.WriteLine(Sha256.Sha256Digest.E1);
            Console.WriteLine(Sha256.Sha256Digest.S0);
            Console.WriteLine(Sha256.Sha256Digest.S1);
            Console.WriteLine(Sha256.Sha256Digest.F1);
            Console.WriteLine(Sha256.Sha256Digest.F2);
        }
    }
}
