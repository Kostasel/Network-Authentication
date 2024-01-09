//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet.Broadcast;

namespace NetworkAuth
{
    //Client -> Server
    public struct HandshakeRequestBroadcast : IBroadcast
    {
		//The Client Computed Public Key
        public byte[] PublicKey;
    }

    //Server -> Client
    public struct HandshakeResponseBroadcast : IBroadcast
    {
		//The Server Computed Public key
        public byte[] PublicKey;
		//Random data + Server IV
        public byte[] Randombytes;
    }
    //Client -> Server
    public struct AuthenticationRequestBroadcast : IBroadcast
    {
		//Client username to be authenticated
        public byte[] Username;
        //Length of the Username byte array
        public int usrlen;
        //Password to be authenticated
        public byte[] Password;
        //Length of the Password byte array
        public int passlen;
    }
    //Server -> Client
    public struct AuthenticationResponseBroadcast : IBroadcast
    {
		//Server Authentication response
        public bool Authenticated;
    }
}