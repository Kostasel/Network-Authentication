Here you can find the examples for the authenticators included in this asset.
Change the Username,Password fields in server and client with the correct data
to authenticate or kick the client requesting authentication in your game.

All the data is encrypted prior to being transmitted with Aes 128 bit encryption.
Before the authentication is started the client and server are doing an asymetric 1024 bit
diffie-hellman-merkle key exchange and both agree on a shared key that will be used to encrypt the
authentication data that will be transmitted.

The LoginCanvas Prefab is fully functional and used in the Example Client authenticator scene.
It uses the legacy ui for compatibility reasons and shows how you can use ClientAuthenticator
component on a login screen.

The Working Example Scene has both authenticators for testing
Just run the scene and use Hello World for both username and password
See the console for useful information or errors.