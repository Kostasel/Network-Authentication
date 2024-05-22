# Network-Authentication
An Authentication and Data encryption library for FishNet networking solution.
Compatible with Unity 2019 and above.

#The Network Authentication

ByteTransforms.cs
The methods in this class are used to create a dependency with the
data or encrypted data.













IntermediateLayer\FastTransformLayer.cs
The methods in this class are used to change the data bytes in the
array with the bytes from the ByteTransforms transform byte array.














Encryptor.cs
The methods in this class are used to aquire,encrypt and decrypt data
with the shared key that has been established(Agreed) in the handshaking proccess between client and server. The key is generated
and aquired from the KeyGenerator class.











KeyGenerator.cs
The methods in this class are used to create the asymetric keys between client and server. They also use those keys to generate
the shared key(shared secret) that has been agreed between client and server. The asymetric keys are created from 2048 bit
(safe)primes.

CryptoTransforms.cs
The methods in this class deliver a prime selected from an array of 2048 bit primes to the calling method.
