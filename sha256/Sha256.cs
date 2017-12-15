using System;
using System.Linq;
using System.Linq.Expressions;

namespace sha256
{
    public static class Sha256Extensions
    {
        public static string ToHex(this uint[] digit)
        {
            return string.Join(" ", digit.Select(x => x.ToString("X08")));
        }
    }

    public class Sha256
    {
        public class Sha256Digest
        {
            /* SHA-256 Constants
            * (represent the first 32 bits of the fractional parts of the
            * cube roots of the first sixty-four prime numbers)
            */
            private static readonly uint[] K =
            {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };

            private readonly uint[] _digest = new uint[8];

            private readonly uint[] _w = new uint[64];

            private byte[] _m;
            private ulong _messageLength, _blocksQty;

            public static Expression<Func<uint, int, uint>> Rotr => (x, n) => (x >> n) ^ (x << (32 - n));
            private static Expression<Func<uint, uint, uint, uint>> Ch => (x, y, z) => (x & y) ^ (~x & z);
            private static Expression<Func<uint, uint, uint, uint>> Maj => (x, y, z) => (x & y) ^ (x & z) ^ (y & z);

            public static Expression<Func<uint, uint>> E0
            {
                get
                {
                    var x = Expression.Parameter(typeof(uint), "x");
                    return Expression.Lambda<Func<uint, uint>>(
                        Expression.ExclusiveOr(
                            Expression.ExclusiveOr(Expression.Invoke(Rotr, x, Expression.Constant(2)),
                                Expression.Invoke(Rotr, x, Expression.Constant(13))),
                            Expression.Invoke(Rotr, x, Expression.Constant(22))), x);
                }
            }

            public static Expression<Func<uint, uint>> E1
            {
                get
                {
                    var x = Expression.Parameter(typeof(uint), "x");
                    return Expression.Lambda<Func<uint, uint>>(
                        Expression.ExclusiveOr(
                            Expression.ExclusiveOr(Expression.Invoke(Rotr, x, Expression.Constant(6)),
                                Expression.Invoke(Rotr, x, Expression.Constant(11))),
                            Expression.Invoke(Rotr, x, Expression.Constant(25))), x);
                }
            }

            public static Expression<Func<uint, uint>> S1
            {
                get
                {
                    var x = Expression.Parameter(typeof(uint), "x");
                    return Expression.Lambda<Func<uint, uint>>(
                        Expression.ExclusiveOr(
                            Expression.ExclusiveOr(Expression.Invoke(Rotr, x, Expression.Constant(17)),
                                Expression.Invoke(Rotr, x, Expression.Constant(19))),
                            Expression.RightShift(x, Expression.Constant(10))), x);
                }
            }

            public static Expression<Func<uint, uint>> S0
            {
                get
                {
                    var x = Expression.Parameter(typeof(uint), "x");
                    return Expression.Lambda<Func<uint, uint>>(
                        Expression.ExclusiveOr(
                            Expression.ExclusiveOr(Expression.Invoke(Rotr, x, Expression.Constant(7)),
                                Expression.Invoke(Rotr, x, Expression.Constant(18))),
                            Expression.RightShift(x, Expression.Constant(3))), x);
                }
            }

            public static Expression<Func<uint, uint, uint, uint, int, uint[], uint>> F1
            {
                get
                {
                    var e = Expression.Parameter(typeof(uint), "e");
                    var f = Expression.Parameter(typeof(uint), "f");
                    var g = Expression.Parameter(typeof(uint), "g");
                    var h = Expression.Parameter(typeof(uint), "h");
                    var i = Expression.Parameter(typeof(int), "i");
                    var w = Expression.Parameter(typeof(uint[]), "w");
                    return Expression.Lambda<Func<uint, uint, uint, uint, int, uint[], uint>>(
                        Expression.Add(Expression.Add(
                            Expression.Add(Expression.Add(h, Expression.Invoke(E1, e)), Expression.Invoke(Ch, e, f, g)),
                            Expression.ArrayIndex(Expression.Constant(K), i)), Expression.ArrayIndex(w, i)),
                        e, f, g, h, i, w);
                }
            }

            public static Expression<Func<uint, uint, uint, uint>> F2
            {
                get
                {
                    var a = Expression.Parameter(typeof(uint), "a");
                    var b = Expression.Parameter(typeof(uint), "b");
                    var c = Expression.Parameter(typeof(uint), "c");
                    return Expression.Lambda<Func<uint, uint, uint, uint>>(
                        Expression.Add(Expression.Invoke(E0, a), Expression.Invoke(Maj, a, b, c)),
                        a, b, c);
                }
            }

            private void InitHs()
            {
                /* SHA-256 initial hash value
                * The first 32 bits of the fractional parts of the square roots
                * of the first eight prime numbers
                */
                _digest[0] = 0x6a09e667;
                _digest[1] = 0xbb67ae85;
                _digest[2] = 0x3c6ef372;
                _digest[3] = 0xa54ff53a;
                _digest[4] = 0x510e527f;
                _digest[5] = 0x9b05688c;
                _digest[6] = 0x1f83d9ab;
                _digest[7] = 0x5be0cd19;
            }

            public uint[] Hash(byte[] message)
            {
                _messageLength = (ulong) message.LongLength;
                var zeroBitsToAddQty = 512 - (int) ((_messageLength * 8 + 1 + 64) % 512);
                _m = new byte[(_messageLength * 8 + 1 + 64 + (ulong) zeroBitsToAddQty) / 8];
                Array.Copy(message, _m, message.LongLength);
                _m[_messageLength] =
                    128; //set 1-st bit to "1", 7 remaining to "0" (may not work with bit-multiple message!!)
                for (var i = _messageLength + 1; i < (ulong) _m.LongLength - 8; i++)
                    _m[i] = 0;
                var messageBitLengthLittleEndian = BitConverter.GetBytes(_messageLength * 8);
                var messageBitLengthBigEndian = new byte[messageBitLengthLittleEndian.Length];
                for (int i = 0, j = messageBitLengthLittleEndian.Length - 1;
                    i < messageBitLengthLittleEndian.Length;
                    i++, j--)
                    messageBitLengthBigEndian[i] = messageBitLengthLittleEndian[j];
                Array.Copy(messageBitLengthBigEndian, 0, _m, _m.LongLength - 8, 8);

                _blocksQty = (ulong) _m.LongLength / 64;

                InitHs();
                for (ulong i = 0; i < _blocksQty; i++)
                {
                    ExpandBlock(i);
                    ProcessBlock();
                }
                return _digest;
            }

            private void ExpandBlock(ulong blockNumber)
            {
                for (var i = 0; i < 16; i++)
                    _w[i] = Bytes_To_UInt32(_m, blockNumber * 64 + (ulong) i * 4);

                for (var i = 16; i <= 63; i++)
                    _w[i] = _w[i - 16] + S0.Compile()(_w[i - 15]) + _w[i - 7] + S1.Compile()(_w[i - 2]);
            }

            internal static uint Bytes_To_UInt32(byte[] bs, ulong off)
            {
                var n = (uint) bs[off] << 24;
                n |= (uint) bs[++off] << 16;
                n |= (uint) bs[++off] << 8;
                n |= bs[++off];
                return n;
            }

            private void ProcessBlock()
            {
                var a = _digest[0];
                var b = _digest[1];
                var c = _digest[2];
                var d = _digest[3];
                var e = _digest[4];
                var f = _digest[5];
                var g = _digest[6];
                var h = _digest[7];

                for (var i = 0; i < 64; i++)
                {
                    var t1 = F1.Compile()(e, f, g, h, i, _w);
                    var t2 = F2.Compile()(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                _digest[0] += a;
                _digest[1] += b;
                _digest[2] += c;
                _digest[3] += d;
                _digest[4] += e;
                _digest[5] += f;
                _digest[6] += g;
                _digest[7] += h;
            }
        }
    }
}