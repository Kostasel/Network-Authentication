This Component is an intermediate layer for fishnet networking.
It is a Performant & Lightweight that is used to Scramble the outgoing data and Unscramble the incoming.
Used together with the authentication system make them undecryptable while being online(transmited).
It will make it harder for others that try to cheat by changing the packets send from server or client.

Tested under 256 CCU Load and works correctly without affecting server/client performance.

To use it you need to copy and paste this code into the transport manager component of fishnet,
this will auto fill the intermediate layer field in the transport manager for you.
When this code is implemented by fishnet this step won't be needed anymore.
            if (_intermediateLayer == null)
                _intermediateLayer = GetComponent<IntermediateLayer>();
put this code after line 166 in Transportmanager.cs bellow InitializeToServerBundles();
on Fishnet 3.6.7

If you want instead to manually copy it yourself you can go to ServerManager
and copy the lines 185-186 then change them to match the code above and
copy them as pair the instructions above.

When you run the scene make sure the field in
NetworkManager->TransportManager->IntermediateLayer
is filled and says NetworkManager(Fast Transform Layer)