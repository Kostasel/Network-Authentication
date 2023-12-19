//Copyright 2023 Kostasel
//See license.txt for license details

using System;
using System.IO;
using System.Security.Cryptography;
using UnityEngine;

namespace NetworkAuth.Crypto
{
    public sealed class Encryptor : IDisposable
    {
        private Aes crypto;
        private byte[] SharedKey;
        private byte[] RandomBytes;
        private byte[] IV;
        private bool disposedValue;
        private KeyGenerator keygen;
        private int p, g;
        //The Encryption block size(in bytes)
        internal static readonly byte blocksize = 16;
		
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public Encryptor()
        {
            crypto = Aes.Create();
            crypto.KeySize = 128;
            crypto.GenerateIV();
            IV = crypto.IV;
            keygen = new KeyGenerator();
            g = keygen.G;
            p = keygen.P;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public Encryptor(int P, int G)
        {
            crypto = new AesCryptoServiceProvider();
            crypto.KeySize = 128;
            crypto.GenerateIV();
            IV = crypto.IV;
            keygen = new KeyGenerator(P, G);
            g = keygen.G;
            p = keygen.P;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        //The P component of the key
        internal int GetP()
        {
            return p;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        //The G component of the key
        internal int GetG()
        {
            return g;
        }
        //The Public key that will be send
        //Client(PublicKey) -> Server and Server(PublicKey) -> Client
        //and used as the key material for the SharedKey secret.
        public byte[] PublicKey
        {
            get
            {
                if (crypto == null) { return null; }
                return keygen.GetPublicKey().ToByteArray();
            }
        }

        internal byte[] iv
        {
            set
            {
                Debug.Assert(value.Length > 16 || value != null || value.Length < 16);
                if (value == null || value.Length > 16 || value.Length < 16) return;
                crypto.IV = value;
                IV = value;
            }
        }
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        //Gets the IV for the current AES instance.
        internal byte[] GetIV()
        {
            if (IV == null) { IV = crypto.IV; }
            Debug.Assert(IV != null);
            return IV;
        }
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        //Gets the SharedKey key that the server-client agreed to.
        public byte[] GetSharedKey()
        {
            return SharedKey;
        }
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal byte[] GetRandomSalt()
        {
            if (RandomBytes == null)
            {
                RandomBytes = keygen.InternalGetRandomSalt();
                return RandomBytes;
            }
            return RandomBytes;
        }
        //A 128 bit(16 byte) symmetric key based on the SharedKey key computed.
        public void ComputeShared(byte[] ReceivedKeyValue)
        {
            SharedKey = keygen.ComputeShared(ReceivedKeyValue, GetRandomSalt()).ToArray();
            Debug.Assert(SharedKey != null);
            crypto.Key = SharedKey;
        }
        //A 128 bit(16 byte) symmetric key based on the SharedKey key computed.
        public void ComputeSharedKey(byte[] ReceivedKeyValue, byte[] rndbytes)
        {
            SharedKey = keygen.ComputeShared(ReceivedKeyValue, rndbytes).ToArray();
            Debug.Assert(SharedKey != null);
            crypto.Key = SharedKey;
        }
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal byte[] EncryptData(byte[] msgdata)
        {
            MemoryStream CipherMs;
            byte[] encrypteddata;
            if (msgdata.Length < blocksize)
            {
                CipherMs = new MemoryStream(blocksize);
            }
            else
            {
                CipherMs = new();
            }
            crypto.Mode = CipherMode.CBC;
            crypto.Padding = PaddingMode.Zeros;
            ICryptoTransform encryptor = crypto.CreateEncryptor(SharedKey, IV);
            CryptoStream cs = new(CipherMs, encryptor, CryptoStreamMode.Write);
            cs.Write(msgdata, 0, msgdata.Length);
            cs.FlushFinalBlock();
            CipherMs.Flush();
            CipherMs.Position = 0;
            if (msgdata.Length > blocksize)
            {
                encrypteddata = CipherMs.ToArray();
            }
            else
            {
                encrypteddata = new byte[CipherMs.Length];
                CipherMs.Read(encrypteddata,0,(int)CipherMs.Length);
            }
            CipherMs.Dispose();
            cs.Clear();
            cs.Dispose();
            CipherMs = null;
            cs = null;
            return Transforms.TransformValueArray(encrypteddata).ToArray();
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal byte[] DecryptData(byte[] msgdata, int msglength)
        {
            byte[] decryptedData = new byte[msglength];
            crypto.Mode = CipherMode.CBC;
            crypto.Padding = PaddingMode.Zeros;
            MemoryStream DecryptMs = new MemoryStream(Transforms.InvertTransformValueArray(msgdata).ToArray());
            ICryptoTransform decryptor = crypto.CreateDecryptor(SharedKey, IV);
            CryptoStream cs = new(DecryptMs, decryptor, CryptoStreamMode.Read);
            cs.Read(decryptedData, 0, msglength);
            cs.Flush();
            cs.Clear();
            DecryptMs.Dispose();
            cs.Dispose();
            cs = null;
            DecryptMs = null;
            return decryptedData;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        //Cleans the managed and unmanaged resources.
        public void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (crypto != null)
                    {
                        Array.Clear(SharedKey, 0, SharedKey.Length);
                        crypto.Clear();
                        crypto.Dispose();
                        crypto = null;
                        keygen = null;
                    }
                }
                disposedValue = true;
            }
        }

        void IDisposable.Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method.
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}