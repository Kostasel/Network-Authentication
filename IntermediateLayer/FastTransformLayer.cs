//Copyright 2023 Kostasel
//See license.txt for license details

using FishNet.Managing.Transporting;
using System;

namespace NetworkAuth.scramble
{
    /// <summary>
    /// Performant & Lightweight to scramble the outgoing server data and unscramble the incoming.
    /// Used also on the authentication to make it more difficult to modify the packets
    /// while the server - client are authenticating.
    /// </summary>
    public class FastTransformLayer : IntermediateLayer
    {
        //Unscramble(InvertTransform) incoming data.
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public override ArraySegment<byte> HandleIncoming(ArraySegment<byte> src, bool fromServer)
        {
            Span<byte> incoming = new(src.Array, src.Offset, src.Count);

            for (int i = 0; i < incoming.Length; i++)
            {
                incoming[i] = Transforms.InvertByteTransform(ref incoming[i]);
            }
            return incoming.ToArray();
        }

        //Scramble(Transform) outgoing data.
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        public override ArraySegment<byte> HandleOutoing(ArraySegment<byte> src, bool toServer)
        {
            Span<byte> outgoing = new(src.Array, src.Offset, src.Count);

            for (int i = 0; i < outgoing.Length; i++)
            {
                outgoing[i] = Transforms.TransformByte(ref outgoing[i]);
            }
            return outgoing.ToArray();
        }
    }
}