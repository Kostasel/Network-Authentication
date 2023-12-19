//Copyright 2023 Kostasel
//See license.txt for license details

using System;
using System.Text;
using FishNet;
using FishNet.Managing;
using FishNet.Managing.Client;
using FishNet.Transporting;
using NetworkEncrypted.Crypto;
using UnityEngine;

namespace NetworkEncrypted
{
    [DisallowMultipleComponent]
    public class EncryptedChannelClient : MonoBehaviour
    {
        #region Public

        /// Subscribe, if you need to know when you can start sending encrypted messaged.
        /// When false, show errors to the user, as it means that the encrypted channel setup failed.
        /// True - completed successfully, false - completed with an error.
        public event Action<bool> OnHandshakeCompleted
        {
            add
            {
                _handshakeCompletedDelegate?.Invoke(_handshakeCompleted);
                _handshakeCompletedDelegate += value;
            }
            remove => _handshakeCompletedDelegate -= value;
        }

        /// Subscribe to listen to all responses to encrypted requests you've sent. 
        public event Action<string> OnResponseToEncryptedMessage;

        #endregion

        #region Private

        private bool _handshakeCompleted;
        private Action<bool> _handshakeCompletedDelegate;
        private static Encryptor _crypto;

        #endregion

        /// <summary>
        /// Call this from the client, when you want to send a message securely.
        /// </summary>
        public void SendEncryptedMessage(string message)
        {
            NetworkManager networkManager = InstanceFinder.NetworkManager;
            if (!_handshakeCompleted)
            {
                networkManager.LogError("Handshaking failed. Cannot send an encrypted message.");
                return;
            }

            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            EncryptedRequestBroadcast encryptedRequestBroadcast = new()
            {
                EncryptedMessage = _crypto.EncryptData(messageBytes),
                EncryptedMessageLength = messageBytes.Length
            };
            networkManager.Log("Sending encrypted request to server...");
            networkManager.ClientManager.Broadcast(encryptedRequestBroadcast);
        }

        private void OnEnable()
        {
            // Listen for connection state change as client.
            InstanceFinder.ClientManager.OnClientConnectionState += OnClientConnectionState;
        }

        private void OnDisable()
        {
            // Stop listening if this behavior is disabled by the user.
            InstanceFinder.ClientManager.OnClientConnectionState -= OnClientConnectionState;
        }

        /// <summary>
        /// Called when a connection state changes for the local client.
        /// </summary>
        private void OnClientConnectionState(ClientConnectionStateArgs args)
        {
            ClientManager clientManager = InstanceFinder.ClientManager;
            NetworkManager networkManager = InstanceFinder.NetworkManager;
            switch (args.ConnectionState)
            {
                case LocalConnectionState.Started:
                {
                    clientManager.RegisterBroadcast<HandshakeResponseBroadcast>(OnHandshakeResponseBroadcast);
                    networkManager.Log("Listening for Handshake response...");
                    //Listen to response from server.
                    clientManager.RegisterBroadcast<ResponseToEncryptedMsgBroadcast>(OnEncryptedMsgResponseBroadcast);
                    networkManager.Log("Listening for encrypted message responses...");
                    _crypto = new Encryptor(EncryptedChannelServer.EncryptorP, EncryptedChannelServer.EncryptorG);

                    //Send a Handshake request to server.
                    networkManager.Log("Sending handshake request to server...");
                    HandshakeRequestBroadcast handshake = new()
                    {
                        PublicKey = Transforms.TransformValueArray(_crypto.PublicKey).ToArray()
                    };
                    clientManager.Broadcast(handshake);
                    break;
                }
                case LocalConnectionState.Stopped:
                    networkManager.Log("Stopped listening for responses from server...");
                    //Stop listening to handshake response from server.
                    clientManager.UnregisterBroadcast<HandshakeResponseBroadcast>(OnHandshakeResponseBroadcast);
                    //Stop listening to message response from server.
                    clientManager.UnregisterBroadcast<ResponseToEncryptedMsgBroadcast>(OnEncryptedMsgResponseBroadcast);
                    _crypto?.Dispose(true);
                    networkManager.Log("EncryptedChannelClient Stopped.");
                    break;
            }
        }

        /// <summary>
        /// Received on client after server sends an Handshake response.
        /// <see cref="https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange"/>
        /// </summary>
        /// <param name="hsk"></param>
        private void OnHandshakeResponseBroadcast(HandshakeResponseBroadcast hsk, Channel channel)
        {
            NetworkManager networkManager = InstanceFinder.NetworkManager;
            networkManager.Log("Received handshake response from server...");
            //Split the random bytes from the iv
            byte[] data = Transforms.InvertTransformValueArray(hsk.Randombytes).ToArray();
            Span<byte> rndBytes = new(data, 0, 64);
            Span<byte> iv = new(data, 64, 16);
            //Use the public key received to compute the SharedKey key.
            networkManager.Log("Computing the SharedKey key based on the public key received from server...");
            _crypto.ComputeSharedKey(Transforms.InvertTransformValueArray(hsk.PublicKey).ToArray(), rndBytes.ToArray());
            //Set the iv received from server form the handshake so the server/client can decrypt each other.
            _crypto.iv = iv.ToArray();
            if (_crypto.PublicKey.Length > 0 && _crypto.GetSharedKey().Length > 0)
            {
                //The handshake is now completed.
                _handshakeCompleted = true;
                networkManager.Log("Handshake Successful.");
            }
            else
            {
                //Something happened and the handshake has failed to complete.
                _handshakeCompleted = false;
                networkManager.LogError("Handshake Failed.");
            }

            _handshakeCompletedDelegate?.Invoke(_handshakeCompleted);
        }

        /// <summary>
        /// Received on client after server sends a response to previously sent encrypted message.
        /// </summary>
        /// <param name="response"></param>
        private void OnEncryptedMsgResponseBroadcast(ResponseToEncryptedMsgBroadcast response, Channel channel)
        {
            InstanceFinder.NetworkManager.Log("Received encrypted message response from server...");
            OnResponseToEncryptedMessage?.Invoke(response.Response);
        }
    }
}