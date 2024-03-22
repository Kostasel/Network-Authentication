This Component is an intermediate layer for fishnet networking.
To be able to work it needs to be assigned inside 
NetworkManager->TransportManager component in IntermediateLayer field.
It is a Performant & Lightweight that is used to Scramble the outgoing data and Unscramble the incoming.
Used together with the authentication system make them undecryptable while being online(transmited).
It will make it harder for others that try to cheat by changing the packets send from server or client.

When you run the scene make sure the field in
NetworkManager->TransportManager->IntermediateLayer
is filled and says Fast Transform Layer.
