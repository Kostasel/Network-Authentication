//Copyright 2023 Kostasel
//See license.txt for license details

using System;

namespace NetworkEncrypted
{
    internal readonly ref struct Transforms
    {
        private static readonly byte[] transform = new byte[256]
        {
              0x36,  0x94,  0x89,  0xcb,  0x77,  0x96,  0xd2,  0x4b,  0x05,  0xf7,  0xab,  0xc5,  0x6d,  0xa1,  0xd6,  0x5b,
              0x61,  0x91,  0xe7,  0xd0,  0x1f,  0xa9,  0x43,  0x1d,  0x9b,  0xbe,  0xf4,  0xb8,  0x42,  0x63,  0x87,  0xbb,
              0x02,  0x58,  0xc3,  0xac,  0xe4,  0xe5,  0xeb,  0xb3,  0x83,  0x70,  0x64,  0x20,  0x57,  0x08,  0x60,  0x85,
              0x2f,  0x90,  0x07,  0xee,  0x23,  0x33,  0x81,  0x12,  0x14,  0xea,  0x39,  0x21,  0x62,  0xcd,  0x28,  0x2e,
              0x2c,  0xf6,  0xdd,  0x25,  0xbc,  0x11,  0xa7,  0xe6,  0xfd,  0x53,  0x98,  0x9c,  0x38,  0x1b,  0x5c,  0x54,
              0x75,  0x95,  0x26,  0x00,  0x09,  0x3b,  0x44,  0x9d,  0x15,  0x5d,  0x1c,  0x9a,  0x5f,  0xc9,  0xa4,  0x78,
              0x5a,  0xf3,  0x0b,  0x0c,  0xe9,  0x0a,  0x06,  0x3e,  0x71,  0xe1,  0xfa,  0xf5,  0x7f,  0x65,  0x19,  0xdf,
              0x8e,  0x32,  0xfb,  0x74,  0x50,  0xd9,  0x72,  0x24,  0x45,  0x0f,  0x69,  0x76,  0xda,  0x41,  0xb1,  0xdb,
              0x79,  0x80,  0x3a,  0x49,  0xe8,  0xbf,  0x73,  0x16,  0x18,  0x8d,  0xce,  0xa3,  0x0e,  0xc6,  0xef,  0xe3,
              0xd7,  0x99,  0x6e,  0x35,  0xfc,  0xaf,  0xa2,  0xc1,  0xde,  0xc2,  0x1e,  0xd1,  0x6c,  0xf1,  0xaa,  0x7e,
              0x8c,  0x52,  0xd4,  0x4a,  0x7c,  0x93,  0xf0,  0xe2,  0xd8,  0x66,  0x04,  0x9e,  0x84,  0x3c,  0x13,  0xae,
              0x86,  0x88,  0xa5,  0x68,  0xd3,  0x37,  0x3d,  0x56,  0x6a,  0x5e,  0x7a,  0xad,  0xc8,  0xb2,  0x40,  0x67,
              0x0d,  0xb7,  0x46,  0x7d,  0xa6,  0x82,  0x6b,  0x3f,  0x34,  0x22,  0xb0,  0xc0,  0x29,  0x4e,  0x59,  0x7b,
              0xc7,  0x31,  0xba,  0x47,  0xfe,  0xc4,  0xd5,  0xe0,  0x92,  0xb9,  0x10,  0xa0,  0x8b,  0xed,  0x55,  0x97,
              0xca,  0x1a,  0xf9,  0x2a,  0xcc,  0xf2,  0x4c,  0x51,  0x03,  0x30,  0x4d,  0xf8,  0xb4,  0xbd,  0xcf,  0x48,
              0xec,  0x2b,  0x9f,  0xff,  0x27,  0x17,  0xb6,  0x8f,  0x8a,  0xb5,  0x01,  0xa8,  0x6f,  0x4f,  0xdc,  0x2d
        };

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static byte TransformByte(ref byte input)
        {
            Span<byte> transforms = stackalloc byte[256];
            transforms = transform;
            return transforms[input];
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static byte TransformByte(byte input)
        {
            return TransformByte(ref input);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static byte Transform(byte input)
        {
            return TransformByte(ref input);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static byte TransformByte(ref int input)
        {
            ReadOnlySpan<byte> transforms = stackalloc byte[256];
            transforms = transform;
            return transforms[input];
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static Span<byte> TransformValueArray(int value)
        {
            return TransformValueArray(ref value);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static Span<byte> TransformValueArray(ref int value)
        {
            Span<byte> data = BitConverter.GetBytes(value).AsSpan();
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = TransformByte(ref data[i]);
            };
            return data;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static Span<byte> TransformValueArray(uint value)
        {
            Span<byte> data = BitConverter.GetBytes(value).AsSpan();
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = TransformByte(ref data[i]);
            };
            return data;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static Span<byte> TransformValueArray(byte[] value)
        {
            Span<byte> data = value.AsSpan(0, value.Length);
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = TransformByte(ref data[i]);
            };
            return data;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static int TransformValue(int value)
        {
            Span<byte> data = BitConverter.GetBytes(value).AsSpan();
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = TransformByte(ref data[i]);
            };
            return BitConverter.ToInt32(data);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static long TransformValue(long value)
        {
            Span<byte> data = BitConverter.GetBytes(value).AsSpan();
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = TransformByte(ref data[i]);
            };
            return BitConverter.ToInt64(data.ToArray(), 0);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static byte[] TransformValueArray(byte value)
        {
            byte[] data = BitConverter.GetBytes(value);
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = TransformByte(ref data[i]);
            };
            return data;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static uint TransformValue(uint value)
        {
            byte[] data = BitConverter.GetBytes(value);
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = TransformByte(ref data[i]);
            };
            return BitConverter.ToUInt32(data);
        }

        private static readonly byte[] invert = new byte[256]
        {
            0x53,  0xfa,  0x20,  0xe8,  0xaa,  0x08,  0x66,  0x32, 0x2d, 0x54, 0x65, 0x62, 0x63, 0xc0, 0x8c, 0x79,
            0xda,  0x45,  0x37,  0xae,  0x38,  0x58,  0x87,  0xf5, 0x88, 0x6e, 0xe1, 0x4d, 0x5a, 0x17, 0x9a, 0x14,
            0x2b,  0x3b,  0xc9,  0x34,  0x77,  0x43,  0x52,  0xf4, 0x3e, 0xcc, 0xe3, 0xf1, 0x40, 0xff, 0x3f, 0x30,
            0xe9,  0xd1,  0x71,  0x35,  0xc8,  0x93,  0x00,  0xb5, 0x4c, 0x3a, 0x82, 0x55, 0xad, 0xb6, 0x67, 0xc7,
            0xbe,  0x7d,  0x1c,  0x16,  0x56,  0x78,  0xc2,  0xd3, 0xef, 0x83, 0xa3, 0x07, 0xe6, 0xea, 0xcd, 0xfd,
            0x74,  0xe7,  0xa1,  0x49,  0x4f,  0xde,  0xb7,  0x2c, 0x21, 0xce, 0x60, 0x0f, 0x4e, 0x59, 0xb9, 0x5c,
            0x2e,  0x10,  0x3c,  0x1d,  0x2a,  0x6d,  0xa9,  0xbf, 0xb3, 0x7a, 0xb8, 0xc6, 0x9c, 0x0c, 0x92, 0xfc,
            0x29,  0x68,  0x76,  0x86,  0x73,  0x50,  0x7b,  0x04, 0x5f, 0x80, 0xba, 0xcf, 0xa4, 0xc3, 0x9f, 0x6c,
            0x81,  0x36,  0xc5,  0x28,  0xac,  0x2f,  0xb0,  0x1e, 0xb1, 0x02, 0xf8, 0xdc, 0xa0, 0x89, 0x70, 0xf7,
            0x31,  0x11,  0xd8,  0xa5,  0x01,  0x51,  0x05,  0xdf, 0x4a, 0x91, 0x5b, 0x18, 0x4b, 0x57, 0xab, 0xf2,
            0xdb,  0x0d,  0x96,  0x8b,  0x5e,  0xb2,  0xc4,  0x46, 0xfb, 0x15, 0x9e, 0x0a, 0x23, 0xbb, 0xaf, 0x95,
            0xca,  0x7e,  0xbd,  0x27,  0xec,  0xf9,  0xf6,  0xc1, 0x1b, 0xd9, 0xd2, 0x1f, 0x44, 0xed, 0x19, 0x85,
            0xcb,  0x97,  0x99,  0x22,  0xd5,  0x0b,  0x8d,  0xd0, 0xbc, 0x5d, 0xe0, 0x03, 0xe4, 0x3d, 0x8a, 0xee,
            0x13,  0x9b,  0x06,  0xb4,  0xa2,  0xd6,  0x0e,  0x90, 0xa8, 0x75, 0x7c, 0x7f, 0xfe, 0x42, 0x98, 0x6f,
            0xd7,  0x69,  0xa7,  0x8f,  0x24,  0x25,  0x47,  0x12, 0x84, 0x64, 0x39, 0x26, 0xf0, 0xdd, 0x33, 0x8e,
            0xa6,  0x9d,  0xe5,  0x61,  0x1a,  0x6b,  0x41,  0x09, 0xeb, 0xe2, 0x6a, 0x72, 0x94, 0x48, 0xd4, 0xf3
        };


        
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static byte InvertByteTransform(ref byte input)
        {
            Span<byte> Invert = stackalloc byte[256];
            Invert = invert;
            return Invert[input];
        }

        
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static byte InvertByteTransform(ref int input)
        {
            Span<byte> Invert = stackalloc byte[256];
            Invert = invert;
            return Invert[input];
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static Span<byte> InvertTransformValueArray(int value)
        {
            return InvertTransformValueArray(ref value);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static Span<byte> InvertTransformValueArray(ref int value)
        {
            Span<byte> data = BitConverter.GetBytes(value).AsSpan();
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = InvertByteTransform(ref data[i]);
            };
            return data;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static int InvertTransformValue(int value)
        {
            Span<byte> data = BitConverter.GetBytes(value).AsSpan();
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = InvertByteTransform(ref data[i]);
            };
            return BitConverter.ToInt32(data);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static long InvertTransformValue(long value)
        {
            Span<byte> data = BitConverter.GetBytes(value).AsSpan();
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = InvertByteTransform(ref data[i]);
            };
            return BitConverter.ToInt64(data.ToArray(), 0);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static uint InvertTransformValue(uint value)
        {
            byte[] data = BitConverter.GetBytes(value);
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = InvertByteTransform(ref data[i]);
            };
            return BitConverter.ToUInt32(data);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static byte[] InvertTransformValueArray(uint value)
        {
            byte[] data = BitConverter.GetBytes(value);
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = InvertByteTransform(ref data[i]);
            };
            return data;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static Span<byte> InvertTransformValueArray(byte[] value)
        {
            Span<byte> data = value.AsSpan(0, value.Length);
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = InvertByteTransform(ref data[i]);
            };
            return data;
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static int InvertTransformValueArrayInt(byte[] value)
        {
            return InvertTransformValueArrayInt(ref value);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        internal static int InvertTransformValueArrayInt(ref byte[] value)
        {
            Span<byte> data = value.AsSpan(0, value.Length);
            for (int i = 0; i < data.Length; ++i)
            {
                data[i] = InvertByteTransform(ref data[i]);
            };
            return BitConverter.ToInt32(data);
        }
    }
}
