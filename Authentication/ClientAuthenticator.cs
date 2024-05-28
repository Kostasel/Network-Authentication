//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet;
using FishNet.Authenticating;
using FishNet.Connection;
using FishNet.Transporting;
using FishNet.Managing;
using NetworkAuth.Crypto;
using System;
using System.Text;
using UnityEngine;
using UnityEngine.UI;

namespace NetworkAuth.ClientAuth
{
    [DisallowMultipleComponent]
    public class ClientAuthenticator : MonoBehaviour
    {
        #region Private
        private bool HandshakeCompleted = false;
        private bool AuthenticationCompleted = false;
        private static Encryptor crypto = null;
        #endregion

        #region Serialized.
        /// <summary>
        /// Username to authenticate.
        /// </summary>
        [Tooltip("Username to authenticate.")]
        [SerializeField]
        private InputField username;
        /// <summary>
        /// Password to authenticate.
        /// </summary>
        [Tooltip("Password to authenticate.")]
        [SerializeField]
        private InputField password;
        #endregion

        #region Public
        #endregion

        private void OnEnable()
        {
            //Listen for connection state change.
            InstanceFinder.ClientManager.OnClientConnectionState += OnClientConnectionState;
        }
		
        private void OnDisable()
        {
	    //Stop listening for connection state change if disabled.
	    if (InstanceFinder.ClientManager != null)
            InstanceFinder.ClientManager.OnClientConnectionState -= OnClientConnectionState;
        }

        /// <summary>
        /// Called when a connection state changes for the local client.
        /// </summary>
        private void OnClientConnectionState(ClientConnectionStateArgs args)
        {
            if (args.ConnectionState == LocalConnectionState.Started)
            {
                if (AuthenticationCompleted) return;
                //Listen to Handshake response from server.
                InstanceFinder.ClientManager.RegisterBroadcast<HandshakeResponseBroadcast>(OnHandshakeResponseBroadcast);
                InstanceFinder.NetworkManager.Log("<color=orange>Listening for Handshake response...</color>");
                //Listen to Authentication response from server.
                InstanceFinder.ClientManager.RegisterBroadcast<AuthenticationResponseBroadcast>(OnAuthenticationResponseBroadcast);
                InstanceFinder.NetworkManager.Log("<color=orange>Listening for Authentication response...</color>");
                InstanceFinder.NetworkManager.Log("<color=orange><b>Client Authenticator Started</b></color>");
                //Using static parameters for P and G of Diffie-Hellman algoritm.
                //cause they are strong enough and if changed need to be the same as the server.
                //See CryptoDataTransforms.cs for some P parameters you can choose.
                crypto = new Encryptor(12, 6);

                //Send a Handshake request to server.
                InstanceFinder.NetworkManager.Log("<color=orange><Client>:Sending handshake request...</color>");
                HandshakeRequestBroadcast handshake = new()
                {
                    PublicKey = Transforms.TransformValueArray(crypto.PublicKey).ToArray()
                };
                InstanceFinder.ClientManager.Broadcast(handshake);
            }

            if (args.ConnectionState == LocalConnectionState.Stopped)
            {
                //Stop Listening to response from server.
                InstanceFinder.ClientManager.UnregisterBroadcast<HandshakeResponseBroadcast>(OnHandshakeResponseBroadcast);
                InstanceFinder.NetworkManager.Log("<color=yellow><Client>:Stopped listening for handshake response from server...</color>");
                //Stop Listening to response from server.
                InstanceFinder.ClientManager.UnregisterBroadcast<AuthenticationResponseBroadcast>(OnAuthenticationResponseBroadcast);
                InstanceFinder.NetworkManager.Log("<color=yellow><Client>:Stopped listening for Authentication response from server...</color>");
                crypto?.Dispose(true);
                AuthenticationCompleted = false;
                InstanceFinder.NetworkManager.Log("<color=yellow><b>Client Authenticator Stopped.</b></color>");
            }
        }

        /// <summary>
        /// Received on client after server sends an Handshake response.
        /// </summary>
		/// <see href="https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange"/>
        /// <param name="hsk">The Public key of the server in order to compute a common key.</param>
        private void OnHandshakeResponseBroadcast(HandshakeResponseBroadcast hsk, Channel channel)
        {
            InstanceFinder.NetworkManager.Log("<color=orange><Client>:Received handshake response from server...</color>");
            //Split the random bytes from the iv
            byte[] data = Transforms.InvertTransformValueArray(hsk.Randombytes).ToArray();
            Span<byte> rndbytes = new Span<byte>(data, 0, 64);
            Span<byte> iv = new Span<byte>(data, 64, 16);
            //Use the public key received to compute the SharedKey key.
            InstanceFinder.NetworkManager.Log("<color=orange><Client>:Computing the Shared Key based on the public key received from server...</color>");
            //Set the iv received from server(in the handshake broadcast) so the server/client can decrypt each other.
            crypto.SetIV(iv.ToArray());
            crypto.ComputeClientSharedKey(Transforms.InvertTransformValueArray(hsk.PublicKey).ToArray(), rndbytes.ToArray());
            if (crypto.PublicKey.Length > 0 && crypto.GetSharedKey().Length > 0)
            {
                //The handshake is now completed.
                HandshakeCompleted = true;
                InstanceFinder.NetworkManager.Log("<color=orange><Client>:Handshake Successfull.</color>");
            }
            else
            {
                //Something happened and the handshake has failed to complete.
                HandshakeCompleted = false;
                InstanceFinder.NetworkManager.LogError("<color=red><b><Client>:Handshake Failed.</b></color>");
            }
        }

        /// <summary>
        /// Received on client after server sends an authentication response.
        /// </summary>
        /// <param name="AuthenticationResponseData">The Server Authentication Response</param>
        private void OnAuthenticationResponseBroadcast(AuthenticationResponseBroadcast AuthenticationResponseData, Channel channel)
        {
            InstanceFinder.NetworkManager.Log("<color=orange><Client>:Received authentication response...</color>");
            bool result = AuthenticationResponseData.Authenticated;
            if (result)
            {
                InstanceFinder.NetworkManager.Log("<color=orange><Client>:Authenticated Successfully.</color>");
            }
            else
            {
                InstanceFinder.NetworkManager.Log("<color=yellow><b><Client>:Authentication Failed.</b></color>");
            }
            AuthenticationCompleted = true;
            InstanceFinder.NetworkManager.Log("<color=orange><b><Client>:Authentication Completed.</b></color>");
        }

        /// <summary>
        /// Called when the user presses the login button in the scene
	    /// and sends an authentication request with the provided username and password.
        /// </summary>
        public void AuthenticateClient()
        {
            if (!HandshakeCompleted) { InstanceFinder.NetworkManager.LogError("<color=red><b><Client>:Handshaking failed. Cannot Authenticate.</b></color>"); return; }
            byte[] usrname = Encoding.UTF8.GetBytes(username.text);
            byte[] pass = Encoding.UTF8.GetBytes(password.text);
            AuthenticationRequestBroadcast authenticationRequestData = new()
            {
                Username = crypto.EncryptData(usrname),
                usrlen = usrname.Length,
                Password = crypto.EncryptData(pass),
                passlen = pass.Length
            };
            InstanceFinder.NetworkManager.Log("<color=orange><Client>:Sending Authentication request...</color>");
            InstanceFinder.NetworkManager.ClientManager.Broadcast(authenticationRequestData);
        }

        /// <summary>
        /// Sends an Authentication request with the provided username and password.
        /// </summary>
        public void AuthenticateClient(string username,string password)
        {
            if (!HandshakeCompleted) { InstanceFinder.NetworkManager.LogError("<color=red><b><Client>:Handshaking failed. Cannot Authenticate.</b></color>"); return; }
            byte[] usrname = Encoding.UTF8.GetBytes(username);
            byte[] pass = Encoding.UTF8.GetBytes(password);
            AuthenticationRequestBroadcast authenticationRequestData = new()
            {
                Username = crypto.EncryptData(usrname),
                usrlen = usrname.Length,
                Password = crypto.EncryptData(pass),
                passlen = pass.Length
            };
            InstanceFinder.NetworkManager.Log("<color=orange><Client>:Sending Authentication request...</color>");
            InstanceFinder.NetworkManager.ClientManager.Broadcast(authenticationRequestData);
        }
    }
}
