using System;

namespace NetworkEncrypted.Examples.Authentication
{
    // Sent from server to client
    [Serializable]
    public class AuthenticationResponse
    {
        public bool successful;
        public int failureReasonCode;
        public string failureReasonDescription;
    }
}