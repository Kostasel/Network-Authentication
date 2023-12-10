//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet;
using FishNet.Managing;
using FishNet.Transporting;
using NetworkAuth.Crypto;
using System;
using System.Text;
using UnityEngine;

namespace NetworkAuth.ClientAuth
{
    [DisallowMultipleComponent]
    public class ClientAuthenticator : MonoBehaviour
    {
        #region Private
        private bool HandshakeCompleted = false;
        private bool AuthenticationCompleted = false;
        private static Encryptor crypto = null;
        private bool connectionstateinit = false;
        #endregion

        #region Serialized.
        /// <summary>
        /// Username to authenticate.
        /// </summary>
        [Tooltip("Username to authenticate.")]
        [SerializeField]
        private string _username = "HelloWorld";
        /// <summary>
        /// Password to authenticate.
        /// </summary>
        [Tooltip("Password to authenticate.")]
        [SerializeField]
        private string _password = "HelloWorld";
        #endregion

        private void OnEnable()
        {
            //Listen for connection state change as client.
            InstanceFinder.ClientManager.OnClientConnectionState += OnClientConnectionState;
        }
		
        /// <summary>
        /// Called when a connection state changes for the local client.
        /// </summary>
        private void OnClientConnectionState(ClientConnectionStateArgs args)
        {
            if (args.ConnectionState == LocalConnectionState.Started)
            {
                if (AuthenticationCompleted) return;
                //Listen to response from server.
                InstanceFinder.ClientManager.RegisterBroadcast<HandshakeResponseBroadcast>(OnHandshakeResponseBroadcast);
                InstanceFinder.NetworkManager.Log("Listening for Handshake response...");
                //Listen to response from server.
                InstanceFinder.ClientManager.RegisterBroadcast<AuthenticationResponseBroadcast>(OnAuthenticationResponseBroadcast);
                InstanceFinder.NetworkManager.Log("Listening for Authentication response...");
                //Using static parameters for P and G of Diffie-Hellman algoritm.
                //cause they are strong enough and if changed need to be the same as the server.
                //See CryptoDataTransforms.cs for some P parameters you can choose.
                crypto = new Encryptor(12, 6);

                //Send a Handshake request to server.
                InstanceFinder.NetworkManager.Log("Sending handshake request to server...");
                HandshakeRequestBroadcast handshake = new()
                {
                    PublicKey = Transforms.TransformValueArray(crypto.PublicKey).ToArray()
                };
                InstanceFinder.ClientManager.Broadcast(handshake);
            }

            if (args.ConnectionState == LocalConnectionState.Stopped)
            {
                InstanceFinder.NetworkManager.Log("Stopped listening for responses from server...");
                //Stop Listening to response from server.
                InstanceFinder.ClientManager.UnregisterBroadcast<HandshakeResponseBroadcast>(OnHandshakeResponseBroadcast);
                //Stop Listening to response from server.
                InstanceFinder.ClientManager.UnregisterBroadcast<AuthenticationResponseBroadcast>(OnAuthenticationResponseBroadcast);
                if (crypto != null) crypto.Dispose(true);
                AuthenticationCompleted = false;
                InstanceFinder.NetworkManager.Log("Client Authenticator Stopped.");
            }
        }

        /// <summary>
        /// Received on client after server sends an Handshake response.
        /// <see cref="https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange"/>
        /// </summary>
        /// <param name="hsk"></param>
        private void OnHandshakeResponseBroadcast(HandshakeResponseBroadcast hsk)
        {
            InstanceFinder.NetworkManager.Log("Received handshake response from server...");
            //Split the random bytes from the iv
            byte[] data = Transforms.InvertTransformValueArray(hsk.Randombytes).ToArray();
            Span<byte> rndbytes = new Span<byte>(data, 0, 64);
            Span<byte> iv = new Span<byte>(data, 64, 16);
            //Use the public key received to compute the SharedKey key.
            InstanceFinder.NetworkManager.Log("Computing the SharedKey key based on the public key received from server...");
            crypto.ComputeSharedKey(Transforms.InvertTransformValueArray(hsk.PublicKey).ToArray(), rndbytes.ToArray());
            //Set the iv received from server form the handshake so the server/client can decrypt each other.
            crypto.iv = iv.ToArray();
            if (crypto.PublicKey.Length > 0 && crypto.GetSharedKey().Length > 0)
            {
                //The handshake is now completed.
                HandshakeCompleted = true;
                InstanceFinder.NetworkManager.Log("Handshake Successfull.");
            }
            else
            {
                //Something happened and the handshake has failed to complete.
                HandshakeCompleted = false;
                InstanceFinder.NetworkManager.LogError("Handshake Failed.");
            }
        }

        /// <summary>
        /// Received on client after server sends an authentication response.
        /// </summary>
        /// <param name="rb"></param>
        private void OnAuthenticationResponseBroadcast(AuthenticationResponseBroadcast arb)
        {
            InstanceFinder.NetworkManager.Log("Received authentication response from server...");
            bool result = arb.Authenticated;
            if (result)
            {
                InstanceFinder.NetworkManager.Log("Authenticated Successfully.");
            }
            else
            {
                InstanceFinder.NetworkManager.LogWarning("Authentication Failed.");
            }
            AuthenticationCompleted = true;
            InstanceFinder.NetworkManager.Log("Authentication Completed.");
        }

        /// <summary>
        /// Called when the user presses the login button on the scene.
        /// </summary>
        public void AuthenticateClient()
        {
            if (!HandshakeCompleted) { InstanceFinder.NetworkManager.LogError("Handshaking failed. Cannot Authenticate."); return; }
            //Calculate padding:
            //Login and password field in example is limited to 15 chars.
            //If you want to have more than 15 chars or the bytes in the byte array
            //exceed 16 you need to add a new block(1 block = 16 bytes)
            //and calculate the usr_pad_count and pass_pad_count with the new value.
            //ex:blocksize was 16 but you have 17 bytes in byte array
            //you need to add 16 bytes(a new block) to blocksize variable,
            //blocksize is now 32(bytes)(16 + 16) - 17(array length).
            int blocksize = 16;
            byte[] usrname = Encoding.UTF8.GetBytes(_username);
            byte[] pass = Encoding.UTF8.GetBytes(_password);
            AuthenticationRequestBroadcast arb = new()
            {
                Username = crypto.EncryptData(usrname),
                //16 = aes encryption block size
                usr_pad_count = (blocksize - usrname.Length),
                Password = crypto.EncryptData(pass),
                //16 = aes encryption block size
                pass_pad_count = (blocksize - pass.Length)
            };
            InstanceFinder.NetworkManager.Log("Sending Authentication request to server...");
            InstanceFinder.NetworkManager.ClientManager.Broadcast(arb);
        }
    }
}