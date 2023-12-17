using System;
using FishNet.Authenticating;
using FishNet.Connection;
using FishNet.Managing;
using NetworkEncrypted;
using UnityEngine;

namespace Network_Authentication.Examples.Authentication
{
    public class ServerAuthenticator : Authenticator
    {
        public override event Action<NetworkConnection, bool> OnAuthenticationResult;

        private const string UsernameForTesting = "Hello";
        private const string PasswordForTesting = "World!";
        private EncryptedChannelServer _encryptedChannelServer;

        public override void InitializeOnce(NetworkManager networkManager)
        {
            // Setup our encrypted communication channel
            _encryptedChannelServer = new EncryptedChannelServer();
            _encryptedChannelServer.InitializeChannel(networkManager);
            // Start listening to requests from clients.
            _encryptedChannelServer.OnEncryptedRequestFromClient += _OnEncryptedMessageReceived;
            base.InitializeOnce(networkManager);
        }

        private void _OnEncryptedMessageReceived(NetworkConnection connection, string messageString)
        {
            AuthenticationRequest clientRequest = JsonUtility.FromJson<AuthenticationRequest>(messageString);

            // If one of those is null, it could be a different encrypted message (not related to auth), as
            // JsonUtility.FromJson() fills the object with default values if json keys for fields haven't been found.
            //
            // You can set up it better, having all messages contain "messageId" field, for example, and checking it.
            if (clientRequest.username == null || clientRequest.password == null) return;

            // Check client username and password.
            if (clientRequest.username == UsernameForTesting && clientRequest.password == PasswordForTesting)
            {
                _HandleAuthSuccess(connection);
            }
            else
            {
                _HandleAuthFailed(connection);
            }
        }

        private void _HandleAuthSuccess(NetworkConnection connection)
        {
            AuthenticationResponse authenticationResponse = new()
            {
                successful = true
            };
            _encryptedChannelServer.SendResponseToAnEncryptedMessage(
                connection,
                JsonUtility.ToJson(authenticationResponse)
            );
            OnAuthenticationResult?.Invoke(connection, true);
        }

        private void _HandleAuthFailed(NetworkConnection connection)
        {
            AuthenticationResponse authenticationResponse = new()
            {
                successful = false,
                failureReasonCode = 400,
                failureReasonDescription = "Provided password is incorrect"
            };
            _encryptedChannelServer.SendResponseToAnEncryptedMessage(
                connection,
                JsonUtility.ToJson(authenticationResponse)
            );
        }
    }
}