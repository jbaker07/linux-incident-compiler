//! Shared state for deduplication, rate-limiting, and change tracking across all sensors

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type StateStore = Mutex<InternalState>;

struct InternalState {
    seen: HashMap<String, u64>,      // "sensor:key" -> timestamp
    hashes: HashMap<String, String>, // "sensor:path" -> hash
    last_emit: HashMap<String, u64>, // "sensor:key" -> timestamp
}

static STATE: OnceLock<StateStore> = OnceLock::new();

fn get_state() -> &'static StateStore {
    STATE.get_or_init(|| {
        Mutex::new(InternalState {
            seen: HashMap::new(),
            hashes: HashMap::new(),
            last_emit: HashMap::new(),
        })
    })
}

/// Returns true if key was never seen before; records first sighting
pub fn seen_once(sensor: &str, key: &str) -> bool {
    let state_key = format!("{}:{}", sensor, key);
    let now = now_ms();
    let mut state = get_state().lock().unwrap();

    if state.seen.contains_key(&state_key) {
        false
    } else {
        state.seen.insert(state_key, now);
        true
    }
}

/// Returns true if hash changed for path; records new hash
pub fn changed_hash(sensor: &str, path: &str, new_hash: &str) -> bool {
    let state_key = format!("{}:{}", sensor, path);
    let mut state = get_state().lock().unwrap();

    if let Some(old_hash) = state.hashes.get(&state_key) {
        if old_hash != new_hash {
            state.hashes.insert(state_key, new_hash.to_string());
            true
        } else {
            false
        }
    } else {
        state.hashes.insert(state_key, new_hash.to_string());
        true // First time seeing this path
    }
}

/// Returns true if enough time has passed since last emit; records new emission
pub fn rate_limit(sensor: &str, key: &str, window_ms: u64) -> bool {
    let state_key = format!("{}:{}", sensor, key);
    let now = now_ms();
    let mut state = get_state().lock().unwrap();

    if let Some(&last_time) = state.last_emit.get(&state_key) {
        if now.saturating_sub(last_time) >= window_ms {
            state.last_emit.insert(state_key, now);
            true
        } else {
            false
        }
    } else {
        state.last_emit.insert(state_key, now);
        true
    }
}

/// Get current time in milliseconds
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
