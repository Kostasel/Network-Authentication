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
                //Using static parameters for P and G of Diffie-Hellman algoritm,
                //cause they are strong enough and if changed needs to be the same as the client.
                //You can also use Encryptor constructor without parameters in order to get random
                //parameters for P and G but you need to send G to client first before handshake
                //can continue.
                //Note: Only G represents a number that is given to encryptor class.
                //      P represents an index to an array in CryptoDataTransforms class.
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
        /// <param name="handshakeRequestData">The broadcast that contains the public key of the client in order to compute a shared key.</param>
        ///
        private void OnHandshakeRequestBroadcast(NetworkConnection conn, HandshakeRequestBroadcast handshakeRequestData, Channel channel)
        {
            NetworkManager.Log("<color=orange><Server>:Received handshake request...</color>");
            byte[] result = new byte[64 + 16];
            //Compute the shared secret(shared key)based on the public key received.
            NetworkManager.Log("<color=orange><Server>:Computing the Shared Key based on the public key received...</color>");
            crypto.ComputeServerShared(Transforms.InvertTransformValueArray(handshakeRequestData.PublicKey).ToArray());
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
            Buffer.BlockCopy(crypto.GetRandomSalt(), 0, result, 0, 64);
            Buffer.BlockCopy(crypto.GetIV(), 0, result, 64, 16);
            
            HandshakeResponseBroadcast handshakeResponseData = new()
            {
                PublicKey = Transforms.TransformValueArray(crypto.PublicKey).ToArray(),
                Randombytes = Transforms.TransformValueArray(result).ToArray()
            };
            SendHandshakeResponse(conn, handshakeResponseData);
        }

        /// <summary>
        /// Received on server when a client sends the AuthenticationRequest broadcast message.
        /// </summary>
        /// <param name="conn">Connection sending broadcast.</param>
        /// <param name="ClientLoginData">The client login details for authentication.</param>
        private void OnAuthenticationRequestBroadcast(NetworkConnection conn, AuthenticationRequestBroadcast ClientLoginData, Channel channel)
        {
            bool authenticationResult;

            //We can't begin an authentication session if the client and server haven't agreed
            //on a SharedKey key.
            if (!HandshakeCompleted)
            {
                conn.Disconnect(true);
                NetworkManager.LogWarning("<color=yellow><b><Server>:A Client tried to authenticate without completing handshaking.</b></color>");
                return;
            }

            /* If client is already authenticated this could be an attack. Connections
             * are removed when a client disconnects so there is no reason they should
             * already be considered authenticated. */
            if (conn.IsAuthenticated)
            {
                conn.Disconnect(true);
                NetworkManager.LogWarning("<color=yellow><b><Server>:Client Disconnected. Reason: Already Authenticated.<b></color>");
                return;
            }

            NetworkManager.Log("<color=orange><Server>:Validating client details...</color>");
            if (AcquireAndValidateLoginDetails(ClientLoginData))
            {
                authenticationResult = true;
            }
            else
            {
                authenticationResult = false;
            }
            SendAuthenticationResponse(conn, authenticationResult);
            OnAuthenticationResult?.Invoke(conn, authenticationResult);
        }


        /// <summary>
        /// Gets and validates user details.
        /// </summary>
        private bool AcquireAndValidateLoginDetails(AuthenticationRequestBroadcast ClientAuthenticationData)
        {
            //TODO:Implement here your own way of reading the login detail's from a database,playfab,firebase.etc.
            //Here i use only 2 string variables in the class for the username and password(Login Details).
            //see _username, _password fields.
            //It is expected that username and password be a string type.
            bool IsValidUsername = (Encoding.UTF8.GetString(crypto.DecryptData(ClientAuthenticationData.Username, ClientAuthenticationData.usrlen)) == _username);
            bool IsValidPassword = (Encoding.UTF8.GetString(crypto.DecryptData(ClientAuthenticationData.Password, ClientAuthenticationData.passlen)) == _password);
            if (IsValidUsername == true && IsValidPassword == true) return true;
            else return false;
        }

        /// <summary>
        /// Sends an authentication result to a connection.
        /// </summary>
        private void SendAuthenticationResponse(NetworkConnection conn, bool authentication_result)
        {
            NetworkManager.Log("<color=orange><Server>:Sending Authentication response...</color>");
            AuthenticationResponseBroadcast authenticationResponseData = new()
            {
                Authenticated = authentication_result
            };
            NetworkManager.ServerManager.Broadcast(conn, authenticationResponseData, false);
        }

        /// <summary>
        /// Sends an Handshake response to a connection.
        /// </summary>
        private void SendHandshakeResponse(NetworkConnection conn, HandshakeResponseBroadcast ServerResponse)
        {
            NetworkManager.ServerManager.Broadcast(conn, ServerResponse, false);
        }
    }
}
