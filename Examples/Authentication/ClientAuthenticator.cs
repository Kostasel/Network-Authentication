using FishNet;
using FishNet.Managing;
using UnityEngine;
using UnityEngine.UI;

namespace NetworkEncrypted.Examples.Authentication
{
    public class ClientAuthenticator : MonoBehaviour
    {
        [SerializeField] private InputField usernameField;
        [SerializeField] private InputField passwordField;
        [SerializeField] private Button loginButton;

        private EncryptedChannelClient _encryptedChannelClient;

        // We cannot start auth before the encrypted channel handshake is finished.
        private bool _canStartAuth;

        private void Start()
        {
            _encryptedChannelClient = new EncryptedChannelClient();
            loginButton.onClick.AddListener(_AuthenticateClient);
            _encryptedChannelClient.OnHandshakeCompleted += _OnHandshakeCompleted;
        }

        private void _OnHandshakeCompleted(bool success)
        {
            if (success) _canStartAuth = true;
            _encryptedChannelClient.OnHandshakeCompleted -= _OnHandshakeCompleted;
        }

        private void _AuthenticateClient()
        {
            if (!_canStartAuth)
            {
                InstanceFinder.NetworkManager.Log("Encrypted channel handshake isn't completed yet.");
                return;
            }
            
            AuthenticationRequest authRequest = new()
            {
                username = usernameField.text,
                password = passwordField.text
            };
            _encryptedChannelClient.SendEncryptedMessage(JsonUtility.ToJson(authRequest));
            _encryptedChannelClient.OnResponseToEncryptedMessage += _OnResponseToEncryptedMessage;
        }

        private void _OnResponseToEncryptedMessage(string response)
        {
            AuthenticationResponse authenticationResponse = JsonUtility.FromJson<AuthenticationResponse>(response);

            // If all response fields are default, it could be a different encrypted message (not related to auth), as
            // JsonUtility.FromJson() fills the object with default values if json keys for fields haven't been found.
            //
            // You can set up it better, having all messages contain "messageId" field, for example, and checking it.
            if (!authenticationResponse.successful &&
                authenticationResponse.failureReasonCode == 0 &&
                authenticationResponse.failureReasonDescription == null) return;

            // Handle authentication response
            InstanceFinder.NetworkManager.Log(
                authenticationResponse.successful
                    ? "Authenticated Successfully."
                    : "Authentication failed, reason: " + authenticationResponse.failureReasonDescription
            );
        }
    }
}