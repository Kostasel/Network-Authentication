//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet.Authenticating;
using FishNet.Connection;
using FishNet.Managing;
using FishNet.Transporting;
using NetworkAuth.Crypto;
using System;
using System.Text;
using UnityEngine;

namespace NetworkAuth.ServerAuth
{
    /// <summary>
    /// NetworkAuth Authenticator
    /// </summary>
    [DisallowMultipleComponent]
    public class ServerAuthenticator : Authenticator
    {
        #region Private
        private bool HandshakeCompleted = false;
        private NetworkManager manager = null;
        private Encryptor crypto = null;
        #endregion

        #region Public.
        /// <summary>
        /// Called when authenticator has concluded a result for a connection. Boolean is true if authenticated successfully, false if failed.
        /// Server listens for this event automatically.
        /// </summary>
        public override event Action<NetworkConnection, bool> OnAuthenticationResult;
        #endregion

        #region Serialized, Authentication Data.
        /// <summary>
        /// Client Username to authenticate.
        /// </summary>
        //You can use this fields or modify the OnAuthenticationRequestBroadcast
        //In next versions thre will be a rework for managing those fields. 
        [Tooltip("Client Username to authenticate.")]
        [SerializeField]
        private string _username = "HelloWorld";
        /// <summary>
        /// Client Password to authenticate.
        /// </summary>
        [Tooltip("Client Password to authenticate.")]
        [SerializeField]
        private string _password = "HelloWorld";

        /// <summary>
        /// The Client Username that will be authenticated.
        /// </summary>
        public string Username
        {
            set
            {
                _username = value;
            }
        }

        /// <summary>
        /// The Client Password that will be authenticated.
        /// </summary>
        public string Password
        {
            set
            {
                _password = value;
            }
        }
        #endregion

        public override void InitializeOnce(NetworkManager networkManager)
        {
            base.InitializeOnce(networkManager);
            manager = networkManager;
            //Listen for connection state change as Server.
            manager.ServerManager.OnServerConnectionState += OnServerConnectionState;
        }

        private void OnServerConnectionState(ServerConnectionStateArgs serverargs)
        {
            if (serverargs.ConnectionState == LocalConnectionState.Started)
            {
                //Using static parameters for P and G of Diffie-Hellman algoritm.
                //cause they are strong enough and if changed need to be the same as the client.
                //See CryptoDataTransforms.cs for some P parameters you can choose.
                crypto = new Encryptor(12, 6);
                //Listen for handshake broadcast from client.
                manager.ServerManager.RegisterBroadcast<HandshakeRequestBroadcast>(OnHandshakeRequestBroadcast, false);
                manager.Log("Listening for Handshake request...");
                //Listen for AuthenticationRequest broadcast from client.
                manager.ServerManager.RegisterBroadcast<AuthenticationRequestBroadcast>(OnAuthenticationRequestBroadcast, false);
                manager.Log("Listening for Authentication request...");
            }
            if (serverargs.ConnectionState == LocalConnectionState.Stopped)
            {
                manager.ServerManager.UnregisterBroadcast<HandshakeRequestBroadcast>(OnHandshakeRequestBroadcast);
                manager.Log("Stopped Listening for Handshake request...");
                manager.ServerManager.UnregisterBroadcast<AuthenticationRequestBroadcast>(OnAuthenticationRequestBroadcast);
                manager.Log("Stopped Listening for Authentication request...");
            }
        }
        /// <summary>
        /// Received on server when a client sends the HandshakeRequest broadcast message.
        /// </summary>
        /// <see cref="https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange"/>
        /// <param name="conn">Connection sending broadcast.</param>
        /// <param name="hsk">The Public key of the client in order to compute a common key.</param>
        /// 
        private void OnHandshakeRequestBroadcast(NetworkConnection conn, HandshakeRequestBroadcast hsk)
        {
            NetworkManager.Log("Received Handshake request from client...");
            Span<byte> result = stackalloc byte[64 + 16];
            byte[] data = new byte[64 + 16];
            result.Clear();
            //Compute the common private key based on the public key received.
            NetworkManager.Log("Computing the SharedKey key based on the public key received from client...");
            crypto.ComputeShared(Transforms.InvertTransformValueArray(hsk.PublicKey).ToArray());
            //Mark the handshake as completed.
            HandshakeCompleted = true;
            /* Send a HandshakeResponse broadcast message to client with the server
             * public key so the client can also compute the common private key
             * and use it for encrypted communication with the server.*/
            NetworkManager.Log("Sending Server Public Key as a response to the handshake request from client...");
            Array.ConstrainedCopy(crypto.GetRandomSalt(), 0, data, 0, 64);
            Array.ConstrainedCopy(crypto.GetIV(), 0, data, 64, 16);
            result = new Span<byte>(data);
            HandshakeResponseBroadcast hrb = new()
            {
                PublicKey = Transforms.TransformValueArray(crypto.PublicKey).ToArray(),
                Randombytes = Transforms.TransformValueArray(result.ToArray()).ToArray()
            };
            SendHandshakeResponse(conn, hrb);
            Array.Clear(data,0, data.Length);
        }

        /// <summary>
        /// Received on server when a client sends the AuthenticationRequest broadcast message.
        /// </summary>
        /// <param name="conn">Connection sending broadcast.</param>
        /// <param name="arb">The client login details for authentication.</param>
        private void OnAuthenticationRequestBroadcast(NetworkConnection conn, AuthenticationRequestBroadcast arb)
        {
            //We can't begin an authentication session if the client and server haven't agreed
            //on a SharedKey key for the encryption of the transmited data.
            if (!HandshakeCompleted)
            {
                NetworkManager.LogWarning("A Client tried to authenticate without previously completing handshaking.");
                return;
            }

            /* If client is already authenticated this could be an attack. Connections
             * are removed when a client disconnects so there is no reason they should
             * already be considered authenticated. */
            if (conn.Authenticated)
            {
                conn.Disconnect(true);
                NetworkManager.LogWarning("Client Disconnected. Reason: Already Authenticated.");
                return;
            }
            //Check Here the actual user details from your database,playfab, etc.
            //and decide whether to allow the user to login or not.
            //Fill _username and _password fields with your real data.
            NetworkManager.Log("Validating client details...");
            bool ValidUsername = Encoding.UTF8.GetString(crypto.DecryptData(arb.Username, arb.usr_pad_count)) == _username;
            bool ValidPassword = Encoding.UTF8.GetString(crypto.DecryptData(arb.Password, arb.pass_pad_count)) == _password;
            bool result = (ValidUsername && ValidPassword);
            SendAuthenticationResponse(conn, result);
            OnAuthenticationResult?.Invoke(conn, result);
        }

        /// <summary>
        /// Sends an authentication result to a connection.
        /// </summary>
        private void SendAuthenticationResponse(NetworkConnection conn, bool _authenticated)
        {
            NetworkManager.Log("Sending Authentication response to client...");
            AuthenticationResponseBroadcast arb = new()
            {
                Authenticated = _authenticated
            };
            NetworkManager.ServerManager.Broadcast(conn, arb, false);
        }

        /// <summary>
        /// Sends an Handshake response to a connection.
        /// </summary>
        private void SendHandshakeResponse(NetworkConnection conn, HandshakeResponseBroadcast hrb)
        {
            NetworkManager.ServerManager.Broadcast(conn, hrb, false);
        }
    }
}