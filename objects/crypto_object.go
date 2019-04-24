package objects

// A cryptoObject related to a token.
type CryptoObject struct {
	Handle     int
	Attributes Attributes
}

// A map of cryptoobjects
type CryptoObjects map[int]*CryptoObject


// Equals returns true if the maps of cryproobjects are equal.
func (objects CryptoObjects) Equals(objects2 CryptoObjects) bool {
	if len(objects) != len(objects2) {
		return false
	}
	for handle, object := range objects {
		object2, ok := objects2[handle]
		if !ok {
			return false
		}
		if !object.Equals(object2) {
			return false
		}
	}
	return true
}

// Equals returns true if the crypto_objects are equal.
func (object *CryptoObject) Equals(object2 *CryptoObject) bool {
	return object.Handle == object2.Handle &&
		object.Attributes.Equals(object2.Attributes)
}
