use agent_identity_core::NodeIdentity;
use libp2p::{
    PeerId, Swarm, SwarmBuilder, autonat, gossipsub, identify, kad, noise, swarm::NetworkBehaviour,
    tcp, yamux,
};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::io::Error as IoError;
use std::time::Duration;

pub const DEFAULT_TOPIC: &str = "agent-node.mesh.v0";
pub const IDENTIFY_PROTOCOL: &str = "/agent-identity-node/0.1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshEnvelope {
    pub schema_version: String,
    pub sender_peer_id: String,
    pub timestamp: i64,
    pub topic: String,
    pub payload: serde_json::Value,
    pub signature_base64: Option<String>,
}

#[derive(NetworkBehaviour)]
pub struct AgentMeshBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub autonat: autonat::Behaviour,
}

impl AgentMeshBehaviour {
    pub fn add_bootstrap_peer(&mut self, peer_id: PeerId, addr: libp2p::Multiaddr) {
        self.kademlia.add_address(&peer_id, addr);
        self.gossipsub.add_explicit_peer(&peer_id);
    }

    pub fn publish_json(
        &mut self,
        topic: &str,
        envelope: &MeshEnvelope,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let bytes = serde_json::to_vec(envelope)?;
        self.gossipsub
            .publish(gossipsub::IdentTopic::new(topic), bytes)?;
        Ok(())
    }
}

pub async fn build_swarm(
    identity: NodeIdentity,
) -> Result<Swarm<AgentMeshBehaviour>, Box<dyn Error>> {
    let local_key = identity.keypair().clone();
    let local_peer_id = local_key.public().to_peer_id();

    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|err| Box::new(IoError::other(err)) as Box<dyn Error + Send + Sync>)?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|err| Box::new(IoError::other(err)) as Box<dyn Error + Send + Sync>)?;
            let kademlia =
                kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
            let identify = identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.into(),
                key.public(),
            ));
            let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());

            Ok(AgentMeshBehaviour {
                gossipsub,
                kademlia,
                identify,
                autonat,
            })
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

pub fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
