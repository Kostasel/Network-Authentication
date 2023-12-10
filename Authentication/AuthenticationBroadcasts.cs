//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet.Broadcast;

namespace NetworkAuth
{
    //Client -> Server
    public struct HandshakeRequestBroadcast : IBroadcast
    {
        public byte[] PublicKey;
    }

    //Server -> Client
    public struct HandshakeResponseBroadcast : IBroadcast
    {
        public byte[] PublicKey;
        public byte[] Randombytes;
    }
    //Client -> Server
    public struct AuthenticationRequestBroadcast : IBroadcast
    {
        public byte[] Username;
        public int usr_pad_count;
        public byte[] Password;
        public int pass_pad_count;
    }
    //Server -> Client
    public struct AuthenticationResponseBroadcast : IBroadcast
    {
        public bool Authenticated;
    }
}