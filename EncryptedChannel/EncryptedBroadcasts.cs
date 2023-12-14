//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet.Broadcast;

namespace NetworkEncrypted
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
    public struct EncryptedRequestBroadcast : IBroadcast
    {
        public byte[] EncryptedMessage;
        public int EncryptedMessagePadCount;
    }
    //Server -> Client
    //TODO should we make response encrypted as well and just name it "EncryptedResponseBroadcast"? 
    //TODO not sure if it is possible to do a mitm attack for a message from the server.
    public struct ResponseToEncryptedMsgBroadcast : IBroadcast
    {
        public string Response;
    }
}