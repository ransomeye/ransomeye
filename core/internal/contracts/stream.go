package contracts

// StreamUnregister allows unregistering an agent's action stream (e.g. when marked AWOL).
// Implemented by enforcement.ActionDispatcher; health depends only on this contract.
type StreamUnregister interface {
	UnregisterStream(agentID string)
}
