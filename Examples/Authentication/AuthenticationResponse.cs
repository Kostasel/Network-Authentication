using System;

namespace Network_Authentication.Examples.Authentication
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