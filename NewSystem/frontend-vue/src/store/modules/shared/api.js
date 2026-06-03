export function getPayload(response) {
  return response && response.data ? response.data.data : null
}

export function getCollection(response) {
  const payload = getPayload(response)
  return Array.isArray(payload) ? payload : []
}
