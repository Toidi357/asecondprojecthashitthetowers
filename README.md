# Happy Cats

## Design
Same as last project, I split up the code into 2 files, one specifically for the client and one specifically for the server. I did this because it's easier to keep track of states since the client/server do very different things, and there is no source code/documentation for how libtransport exactly behaves. Both client and server had a "state tracker," where they had to go through states 0, 1, 2, 3 until its normal data flow.
State Diagram looked like this:
| State | Client Input    | Client Output     | Server Input       | Server Output       |
|-------|-----------------|-------------------|--------------------|---------------------|
| 0     | send hello      | do nothing        | do nothing         | parse cli hello     |
| 1     | do nothing      | parse ser hello   | send hello         | do nothing          |
| 2     | send finish     | do nothing        | do nothing         | verify finish       |
| 3     | good to go      | good to go        | good to go         | good to go          |


## Problems
The only problem was that the specification should clarify that when calculating MAC digests and signatures, we should be using the serialized TLV, not just the tlv->val
Other than that, project went very smoothly
