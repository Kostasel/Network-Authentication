//Copyright 2023 Kostasel
//See license.txt for license details

using System;
using System.Collections.Generic;
using System.Text;
using FishNet;
using FishNet.Connection;
using FishNet.Managing;
using FishNet.Transporting;
using NetworkAuth.Crypto;
using UnityEngine;

namespace NetworkEncrypted.EncryptedChannelServer
{
    [DisallowMultipleComponent]
    public class EncryptedChannelServer : MonoBehaviour
    {
        #region Public

        /// Using static parameters for P and G of Diffie-Hellman algorithm, because
        /// they are strong enough and if changed need to be the same as the client.
        /// See CryptoTransforms.cs for some P parameters you can choose.
        public const int EncryptorP = 12;
        public const int EncryptorG = 6;

        /// Subscribe, if you need to know the handshake state (e.g. to kick the user).
        /// NetworkConnection: the client we did a handshake with.
        /// bool: True - completed successfully, false - completed with an error.
        public event Action<NetworkConnection, bool> OnHandshakeCompleted
        {
            add => _handshakeCompletedDelegate += value;
            remove => _handshakeCompletedDelegate -= value;
        }

        /// Subscribe to listen to encrypted requests from clients.
        /// NetworkConnection: the client that sent the encrypted message.
        /// string: message content.
        public event Action<NetworkConnection, string> OnEncryptedRequestFromClient
        {
            add => _encryptedRequestFromClientDelegate += value;
            remove => _encryptedRequestFromClientDelegate -= value;
        }

        #endregion

        #region Private

        private readonly Dictionary<NetworkConnection, bool> _handshakeCompleted = new();
        private Action<NetworkConnection, bool> _handshakeCompletedDelegate;
        private Action<NetworkConnection, string> _encryptedRequestFromClientDelegate;
        private Encryptor _crypto;

        #endregion

        /// <summary>
        /// Use this to send a response to a recently received encrypted message.
        /// </summary>
        public void SendResponseToAnEncryptedMessage(NetworkConnection conn, string responseString)
        {
            NetworkManager networkManager = InstanceFinder.NetworkManager;
            networkManager.Log("Sending response to an encrypted request from the client...");
            ResponseToEncryptedMsgBroadcast responseToEncryptedMsgBroadcast = new()
            {
                Response = responseString
            };
            networkManager.ServerManager.Broadcast(conn, responseToEncryptedMsgBroadcast, false);
        }

        private void OnEnable()
        {
            InstanceFinder.NetworkManager.ServerManager.OnServerConnectionState += OnServerConnectionState;
        }

        private void OnDisable()
        {
            InstanceFinder.NetworkManager.ServerManager.OnServerConnectionState -= OnServerConnectionState;
        }

        private void OnServerConnectionState(ServerConnectionStateArgs serverArgs)
        {
            NetworkManager networkManager = InstanceFinder.NetworkManager;
            switch (serverArgs.ConnectionState)
            {
                case LocalConnectionState.Started:
                    _crypto = new Encryptor(EncryptorP, EncryptorG);
                    //Listen for handshake broadcast from client.
                    networkManager.ServerManager.RegisterBroadcast<HandshakeRequestBroadcast>(
                        OnHandshakeRequestBroadcast,
                        false
                    );
                    networkManager.Log("Listening for Handshake request...");
                    //Listen for EncryptedRequestBroadcast from client.
                    networkManager.ServerManager.RegisterBroadcast<EncryptedRequestBroadcast>(
                        OnEncryptedRequestBroadcast,
                        false
                    );
                    networkManager.Log("Listening for encrypted requests...");
                    break;
                case LocalConnectionState.Stopped:
                    networkManager.ServerManager.UnregisterBroadcast<HandshakeRequestBroadcast>(
                        OnHandshakeRequestBroadcast
                    );
                    networkManager.Log("Stopped Listening for Handshake request...");
                    networkManager.ServerManager.UnregisterBroadcast<EncryptedRequestBroadcast>(
                        OnEncryptedRequestBroadcast
                    );
                    networkManager.Log("Stopped Listening for encrypted requests...");
                    break;
            }
        }

        /// <summary>
        /// Received on server when a client sends the HandshakeRequestBroadcast message.
        /// </summary>
        /// <see cref="https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange"/>
        /// <param name="conn">Connection sending broadcast.</param>
        /// <param name="hsk">The Public key of the client in order to compute a common key.</param>
        /// <param name="channel"></param>
        /// 
        private void OnHandshakeRequestBroadcast(NetworkConnection conn, HandshakeRequestBroadcast hsk, Channel channel)
        {
            NetworkManager networkManager = InstanceFinder.NetworkManager;
            networkManager.Log("Received Handshake request from client...");
            Span<byte> result = stackalloc byte[64 + 16];
            byte[] data = new byte[64 + 16];
            result.Clear();
            //Compute the common private key based on the public key received.
            networkManager.Log("Computing the SharedKey key based on the public key received from client...");
            _crypto.ComputeShared(Transforms.InvertTransformValueArray(hsk.PublicKey).ToArray());
            //Mark the handshake as completed for this client.
            _handshakeCompleted.Add(conn, true);
            /* Send a HandshakeResponse broadcast message to client with the server
             * public key so the client can also compute the common private key
             * and use it for encrypted communication with the server.*/
            networkManager.Log("Sending Server Public Key as a response to the handshake request from client...");
            Array.ConstrainedCopy(_crypto.GetRandomSalt(), 0, data, 0, 64);
            Array.ConstrainedCopy(_crypto.GetIV(), 0, data, 64, 16);
            result = new Span<byte>(data);
            HandshakeResponseBroadcast hrb = new()
            {
                PublicKey = Transforms.TransformValueArray(_crypto.PublicKey).ToArray(),
                Randombytes = Transforms.TransformValueArray(result.ToArray()).ToArray()
            };
            SendHandshakeResponse(conn, hrb);
            Array.Clear(data, 0, data.Length);
        }

        /// <summary>
        /// Received on server when a client sends the EncryptedRequestBroadcast message.
        /// </summary>
        /// <param name="conn">Connection sending the broadcast.</param>
        /// <param name="erb">The encrypted data the client has sent.</param>
        private void OnEncryptedRequestBroadcast(NetworkConnection conn, EncryptedRequestBroadcast erb, Channel channel)
        {
            NetworkManager networkManager = InstanceFinder.NetworkManager;
            // We can't receive encrypted messages if the client and server haven't agreed
            // on a SharedKey key for the encryption of the transmitted data.
            if (!_handshakeCompleted[conn])
            {
                networkManager.LogWarning("A Client tried to send an encryptedMessage without completing handshaking.");
                return;
            }

            // We got an encrypted string, decrypt it.
            string decryptedString = Encoding.UTF8.GetString(
                _crypto.DecryptData(erb.EncryptedMessage, erb.EncryptedMessagePadCount)
            );

            // Send it to encrypted request listeners
            _encryptedRequestFromClientDelegate?.Invoke(conn, decryptedString);
        }

        /// <summary>
        /// Sends an Handshake response to a connection.
        /// </summary>
        private void SendHandshakeResponse(NetworkConnection conn, HandshakeResponseBroadcast hrb)
        {
            InstanceFinder.NetworkManager.ServerManager.Broadcast(conn, hrb, false);
        }
    }
}