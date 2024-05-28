//Copyright 2023 Kostasel
//See license.txt for license details

using System;
using System.IO;
using System.Security.Cryptography;
using UnityEngine;
using Protect.KeyProtection;

namespace NetworkAuth.Crypto
{
    public sealed class Encryptor : IDisposable
    {
        private Aes crypto;
        private byte[] ProtecedSharedKey;
        private byte[] RandomBytes;
        private byte[] IV;
        private bool disposedValue;
        private KeyGenerator keygen;
        //The Encryption block size(in bytes)
        internal static readonly byte blocksize = 16;
		
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public Encryptor()
        {
            crypto = Aes.Create();
            crypto.KeySize = 256;
            crypto.GenerateIV();
            IV = crypto.IV;
            keygen = new KeyGenerator();
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public Encryptor(int P, int G)
        {
            crypto = new AesCryptoServiceProvider();
            crypto.KeySize = 256;
            crypto.GenerateIV();
            IV = crypto.IV;
            keygen = new KeyGenerator(P, G);
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
        
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal void SetIV(byte[] value)
        {
            Debug.Assert(value.Length > 16 || value != null || value.Length < 16);
            if (value == null || value.Length > 16 || value.Length < 16) return;
            crypto.IV = value;
            IV = value;
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
        //Gets the SharedSecret(Shared Key) that the server-client agreed to.
        public byte[] GetSharedKey()
        {
            return KeyProtector.Unprotect(ProtecedSharedKey, crypto.IV);
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
        //A 256 bit(32 byte) symmetric key based on the Shared Key computed.
        public void ComputeServerShared(byte[] ReceivedKeyValue)
        {
            byte[] sharedkey = keygen.ComputeShared(ReceivedKeyValue, GetRandomSalt()).ToArray();
            Debug.Assert(sharedkey != null);
            ProtecedSharedKey = KeyProtector.Protect(sharedkey,crypto.IV);
            Debug.Assert(ProtecedSharedKey != null);
            crypto.Key = sharedkey;
            Array.Clear(sharedkey, 0, sharedkey.Length);
        }
        //A 256 bit(32 byte) symmetric key based on the SharedKey key computed.
        public void ComputeClientSharedKey(byte[] ReceivedKeyValue, byte[] rndbytes)
        {
            byte[] sharedkey = keygen.ComputeShared(ReceivedKeyValue, rndbytes).ToArray();
            Debug.Assert(sharedkey != null);
            ProtecedSharedKey = KeyProtector.Protect(sharedkey, crypto.IV);
            Debug.Assert(ProtecedSharedKey != null);
            crypto.Key = sharedkey;
            Array.Clear(sharedkey, 0, sharedkey.Length);
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
            ICryptoTransform encryptor = crypto.CreateEncryptor(GetSharedKey(), crypto.IV);
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
            ICryptoTransform decryptor = crypto.CreateDecryptor(GetSharedKey(), crypto.IV);
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
                        Array.Clear(ProtecedSharedKey, 0, ProtecedSharedKey.Length);
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