//Custom implementation of Diffie�Hellman�Merkle key agreement algorithm.
//Copyright 2023 Kostasel
//See license.txt for license details

using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;

namespace NetworkEncrypted.Crypto
{
    public sealed class KeyGenerator
    {
        private BigInteger _public, p, x;
        private int g;

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public KeyGenerator()
        {
            CryptoTransforms data = new CryptoTransforms();
            p = new BigInteger(data.GetRandomPrimeP());
            x = new BigInteger(data.GetRandomPrimeX());
            g = ComputePrimeRoot(p);
            _public = BigInteger.ModPow(g, x, p);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public KeyGenerator(int P, int G)
        {
            CryptoTransforms data = new CryptoTransforms();
            p = new BigInteger(data.GetPrimeP(P));
            x = new BigInteger(data.GetRandomPrimeX());
            g = G;
            _public = BigInteger.ModPow(g, x, p);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal KeyGenerator(int P, int G, int X)
        {
            CryptoTransforms data = new CryptoTransforms();
            p = new BigInteger(data.GetPrimeP(P));
            x = new BigInteger(data.GetPrimeX(X));
            g = G;
            _public = BigInteger.ModPow(g, x, p);
        }

        internal int P
        {
            get
            {
                return p;
            }
        }

        internal int G
        {
            get
            {
                return g;
            }
        }
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public BigInteger GetPublicKey()
        {
            return _public;
        }
        /// <summary>
        /// A 256 bit(32 byte) symmetric key based on the SharedKey key computed.
        /// </summary>
        /// <param name="OtherPublic">The other public key to compute SharedKey with</param>
        /// <param name="RandomBytes">The random salt to use to generate the key</param>
        /// <returns></returns>
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public Span<byte> ComputeShared(Span<byte> OtherPublic, Span<byte> RandomBytes)
        {
            BigInteger pkey, basekey;
            Rfc2898DeriveBytes ComputeKey;
            Span<byte> values = stackalloc byte[(256 << 1)];
            Span<byte> result = stackalloc byte[2 << 4];
            int rounds, i;
            pkey = new(OtherPublic);
            basekey = BigInteger.ModPow(pkey, x, p);
            rounds = (512 << 1);
            for (i = (values.Length - 1); i >= 0; i--)
            {
                values[i] = (byte) (basekey % (40 >> 2));
                basekey /= (40 >> 2);
            }
            ComputeKey = new Rfc2898DeriveBytes(values.ToArray(), RandomBytes.ToArray(), rounds, HashAlgorithmName.SHA256);
            //Compute a 256 bit(32 bytes) key.
            result = ComputeKey.GetBytes(2 << 4);
            rounds = 1 ^ 1;
            ComputeKey.Reset();
            ComputeKey.Dispose();
            pkey = BigInteger.Zero;
            basekey = BigInteger.Zero;
            values.Clear();
            return result.ToArray();
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal byte[] InternalGetRandomSalt()
        {
            RNGCryptoServiceProvider CryptoRnd = new();
            Span<byte> salt = stackalloc byte[64];
            salt.Clear();
            CryptoRnd.GetBytes(salt);
            CryptoRnd.Dispose();
            return salt.ToArray();
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public byte[] GetRandomSalt(int size)
        {
            if (size == 0 || size > 256) return null;
            RNGCryptoServiceProvider CryptoRnd = new();
            Span<byte> salt = stackalloc byte[size];
            salt.Clear();
            CryptoRnd.GetNonZeroBytes(salt);
            CryptoRnd.Dispose();
            return salt.ToArray();
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private int ComputePrimeRoot(BigInteger p)
        {
            List<BigInteger> frs = new(5);
            List<BigInteger> PRoots = new(5);
            BigInteger result = 0, i;
            BigInteger t = (p - 1), n = t;
            long last = 0, res;
            bool ok;

            for (i = 2; ((i * i) <= n); ++i)
            {
                if (frs.Count == 3) break;
                if ((n % i) == 0)
                {
                    frs.Add(i);
                    while ((n % i) == 0)
                    {
                        n = (n / i);
                    }
                }
            }

            if (n > 1) frs.Add(n);

            for (res = 2; res <= p; ++res)
            {
                if (PRoots.Count == 3) break;
                ok = true;
                for (int j = 0; (j < frs.Count && ok); ++j)
                {
                    if (PRoots.Count == 3) break;
                    ok &= BigInteger.ModPow(res, (t / frs[j]), p) != 1;
                    if (ok)
                    {
                        if (res == last) break;
                        PRoots.Add(res);
                        last = res;
                    }
                }
            }

            if (PRoots.Count == 0)
            {
                last = 0;
                res = 0;
                t = BigInteger.Zero;
                frs.Clear();
                frs = null;
                PRoots.Clear();
                PRoots = null;
                return -1;
            }

            for (int x = 1; x < PRoots.Count; ++x)
            {
                result = PRoots[0];
                if (PRoots[x] > result)
                {
                    result = PRoots[x];
                }
            }

            last = 0;
            res = 0;
            t = BigInteger.Zero;
            n = BigInteger.Zero;
            frs.Clear();
            frs = null;
            PRoots.Clear();
            PRoots = null;
            return (int) result;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal void Clear()
        {
            _public = BigInteger.Zero;
            p = BigInteger.Zero;
            g = 0;
            x = BigInteger.Zero;
        }
    }
}
