/// Here we have a gossip module, which is responsible for gossiping messages between the light
/// client network to provide DAS.
///
///
/// We define a few gossiping operators
///
///


/// Explain various node operators in the system
enum Operator {
    /// This node will maintain full erasure coding of the data per root 
    /// and expose a gossiping interface to other nodes.
    /// It is assumed there is at least one Honest Replication node in the network.
    Replication,
    /// This node will maintain chunks of data and relay them to other nodes who can store them.
    /// These nodes must ensure that the availability of the data is maintained to a degree such
    /// that a sampling rate of 2^-r where r is the sampling rate is maintained.
    GossipChunk,
    /// This node can sample the network for various chunks of data and verify their integrity.
    Sampler
}
