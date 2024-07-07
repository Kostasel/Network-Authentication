using System;

namespace NetworkEncrypted.Examples.Authentication
{
    // Sent from client to server
    [Serializable]
    public class AuthenticationRequest
    {
        public string username;
        public string password;
    }
}