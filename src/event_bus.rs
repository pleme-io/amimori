//! Internal event bus for reactive scheduling.
//!
//! The daemon's actors communicate through typed trigger events on a
//! broadcast channel. Each actor subscribes independently and receives
//! its own copy of every event. Actors that fall behind (lagged) simply
//! miss triggers and rely on their fallback interval — graceful degradation.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Scheduling signals that trigger reactive actor runs.
/// Distinct from `model::Change` — these are internal scheduling commands,
/// not state deltas exposed to gRPC/MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerEvent {
    /// An interface's fields changed (IP, gateway, DNS, up/down).
    InterfaceChanged { interface: String },

    /// A network transition occurred (different gateway/subnet).
    NetworkChanged {
        interface: String,
        old_network_id: String,
        new_network_id: String,
    },

    /// An interface went down.
    InterfaceDown { interface: String },
}

/// Which category of trigger an actor cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerKind {
    InterfaceChanged,
    NetworkChanged,
    InterfaceDown,
}

impl TriggerEvent {
    pub fn kind(&self) -> TriggerKind {
        match self {
            Self::InterfaceChanged { .. } => TriggerKind::InterfaceChanged,
            Self::NetworkChanged { .. } => TriggerKind::NetworkChanged,
            Self::InterfaceDown { .. } => TriggerKind::InterfaceDown,
        }
    }

    pub fn matches(&self, kinds: &[TriggerKind]) -> bool {
        kinds.contains(&self.kind())
    }
}

/// Broadcast event bus. Create once, clone the sender into StateEngine,
/// subscribe receivers into each reactive actor.
pub struct EventBus {
    sender: broadcast::Sender<TriggerEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn sender(&self) -> broadcast::Sender<TriggerEvent> {
        self.sender.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TriggerEvent> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_event_matches_kind() {
        let e = TriggerEvent::NetworkChanged {
            interface: "en0".into(),
            old_network_id: "a".into(),
            new_network_id: "b".into(),
        };
        assert!(e.matches(&[TriggerKind::NetworkChanged]));
        assert!(!e.matches(&[TriggerKind::InterfaceChanged]));
        assert!(e.matches(&[
            TriggerKind::InterfaceChanged,
            TriggerKind::NetworkChanged
        ]));
    }

    #[test]
    fn trigger_event_interface_changed_kind() {
        let e = TriggerEvent::InterfaceChanged {
            interface: "en0".into(),
        };
        assert_eq!(e.kind(), TriggerKind::InterfaceChanged);
    }

    #[tokio::test]
    async fn event_bus_broadcast_delivery() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = TriggerEvent::InterfaceChanged {
            interface: "en0".into(),
        };
        bus.sender().send(event.clone()).unwrap();

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert!(matches!(e1, TriggerEvent::InterfaceChanged { .. }));
        assert!(matches!(e2, TriggerEvent::InterfaceChanged { .. }));
    }

    #[tokio::test]
    async fn event_bus_no_receivers_doesnt_panic() {
        let bus = EventBus::new(16);
        // No subscribers — send should not panic (returns Err but that's fine)
        let _ = bus.sender().send(TriggerEvent::InterfaceDown {
            interface: "en0".into(),
        });
    }
}
