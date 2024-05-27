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
        private string _username;
        /// <summary>
        /// Client Password to authenticate.
        /// </summary>
        [Tooltip("Client Password to authenticate.")]
        [SerializeField]
        private string _password;
        #endregion
        
        public override void InitializeOnce(NetworkManager networkManager)
        {
            base.InitializeOnce(networkManager);
            manager = networkManager;
            //Listen for connection state change.
            manager.ServerManager.OnServerConnectionState += OnServerConnectionState;
        }

        private void OnDisable()
        {
            //Stop listening for connection state change if disabled.
            manager.ServerManager.OnServerConnectionState -= OnServerConnectionState;
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
                manager.Log("<color=orange><Server>:Listening for Handshake request...</color>");
                //Listen for AuthenticationRequest broadcast from client.
                manager.ServerManager.RegisterBroadcast<AuthenticationRequestBroadcast>(OnAuthenticationRequestBroadcast, false);
                manager.Log("<color=orange><Server>:Listening for Authentication request...</color>");
                manager.Log("<color=orange><b>Server Authenticator Started</b></color>");
            }
            if (serverargs.ConnectionState == LocalConnectionState.Stopped)
            {
                manager.ServerManager.UnregisterBroadcast<HandshakeRequestBroadcast>(OnHandshakeRequestBroadcast);
                manager.Log("<color=yellow><Server>:Stopped Listening for Handshake request...</color>");
                manager.ServerManager.UnregisterBroadcast<AuthenticationRequestBroadcast>(OnAuthenticationRequestBroadcast);
                manager.Log("<color=yellow><Server>:Stopped Listening for Authentication request...</color>");
                manager.Log("<color=yellow><b>Server Authenticator Stopped</b></color>");
            }
        }
        /// <summary>
        /// Received on server when a client sends the HandshakeRequest broadcast message.
        /// </summary>
        /// <see href="https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange"/>
        /// <param name="conn">Connection sending broadcast.</param>
        /// <param name="hsk">The Public key of the client in order to compute a common key.</param>
        /// 
        private void OnHandshakeRequestBroadcast(NetworkConnection conn, HandshakeRequestBroadcast hsk, Channel channel)
        {
            NetworkManager.Log("<color=orange><Server>:Received handshake request...</color>");
            Span<byte> result;
            byte[] data = new byte[64 + 16];
            //Compute the common private key based on the public key received.
            NetworkManager.Log("<color=orange><Server>:Computing the Shared Key based on the public key received...</color>");
            crypto.ComputeServerShared(Transforms.InvertTransformValueArray(hsk.PublicKey).ToArray());
            if (crypto.PublicKey.Length > 0 && crypto.GetSharedKey().Length > 0)
            {
                //The handshake is successfull.
            HandshakeCompleted = true;
                NetworkManager.Log("<color=orange><Server>:Handshake Successfull.</color>");
            }
            else
            {
                //Something happened and the handshake has failed to complete.
                HandshakeCompleted = false;
                NetworkManager.LogError("<color=red><b><Client>:Handshake Failed.</b></color>");
                //Disconnect the Client
                conn.Disconnect(true);
            }
            /* Send a HandshakeResponse broadcast message to client with the server
             * public key so the client can also compute the common private key
             * and use it for encrypted communication with the server.*/
            NetworkManager.Log("<color=orange><Server>:Sending Server Public Key as a response to a handshake request...</color>");
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
        private void OnAuthenticationRequestBroadcast(NetworkConnection conn, AuthenticationRequestBroadcast arb, Channel channel)
        {
            //We can't begin an authentication session if the client and server haven't agreed
            //on a SharedKey key for the encryption of the transmited data.
            if (!HandshakeCompleted)
            {
                conn.Disconnect(true);
                NetworkManager.LogWarning("<color=yellow><b><Server>:A Client tried to authenticate without previously completing handshaking.</b></color>");
                return;
            }

            /* If client is already authenticated this could be an attack. Connections
             * are removed when a client disconnects so there is no reason they should
             * already be considered authenticated. */
            if (conn.Authenticated)
            {
                conn.Disconnect(true);
                NetworkManager.LogWarning("<color=yellow><b><Server>:Client Disconnected. Reason: Already Authenticated.<b></color>");
                return;
            }
            //Check Here the actual user details from your database,playfab, etc.
            //and decide whether to allow the user to login or not.
            //Fill _username and _password fields with your real data.
            NetworkManager.Log("<color=orange><Server>:Validating client details...</color>");
            if (AcquireAndValidateLoginDetails(_username,_password))
            {
                result = true;
            }
            else
            {
                result = false;
            }
            SendAuthenticationResponse(conn, result);
            OnAuthenticationResult?.Invoke(conn, result);
        }


        /// <summary>
        /// Gets and validates user details.
        /// </summary>
        /// <param name="username">A username to validate</param>
        /// <param name="password">A password to validate</param>
        private bool AcquireAndValidateLoginDetails(string username,string password)
        {
            //TODO:Implement here your own way of reading the login detail's from the server.
            //Here i use only 2 string variables in the class for the username and password(Login Details).
            //see _username,_password
            //It is expected that username and password be a string type.
            bool ValidUsername = (Encoding.UTF8.GetString(crypto.DecryptData(arb.Username, arb.usrlen)) == username);
            bool ValidPassword = (Encoding.UTF8.GetString(crypto.DecryptData(arb.Password, arb.passlen)) == password);
            if (ValidUsername == true && ValidPassword == true) return true;
            else return false;
        }
        
        /// <summary>
        /// Sends an authentication result to a connection.
        /// </summary>
        private void SendAuthenticationResponse(NetworkConnection conn, bool _authenticated)
        {
            NetworkManager.Log("<color=orange><Server>:Sending Authentication response...</color>");
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
