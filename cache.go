package whois

import (
	"encoding/gob"
	"os"
	"time"
)

//
// kvCacheItem
//
type kvCacheItem struct {
	value      string
	lastUpdate time.Time
	lastAccess time.Time
}

//
// KVCache a simple key Value structure with ttl.
//
type KVCache struct {
	ttl  int
	data map[string]*kvCacheItem
}

//
// Add appends an additional key to the current KVCache.
// If the entry already exist the value and lastUpdate will be updated.
// Returns true if the key did not exist before otherwise false.
//
func (c *KVCache) Add(key string, value string) bool {
	val, ok := c.data[key]

	if ok {
		val.value = value
		val.lastUpdate = time.Now()
		val.lastAccess = time.Now()
	} else {
		c.data[key] = &kvCacheItem{
			value:      value,
			lastUpdate: time.Now(),
			lastAccess: time.Now(),
		}

		return true
	}

	return false
}

//
// Get returns the value for the given or empty string if
// the key does not exist.
// If the key's lastUpdate is older than the ttl allows empty string is returned
//
func (c *KVCache) Get(key string) string {
	val, ok := c.data[key]

	if !ok {
		return ""
	}

	now := time.Now().Add(time.Duration(-1*c.ttl) * time.Second)

	if now.After(val.lastUpdate) {
		return ""
	}

	return val.value
}

//
// Clean removes all entries which are not accassed more than the given time.
//
func (c *KVCache) Clean(ttl time.Duration) {
	now := time.Now().Add(-ttl)

	for k, v := range c.data {
		if v.lastAccess.Before(now) {
			delete(c.data, k)
		}
	}
}

//
// NewCache creates a new KVCache instance.
//
func NewCache(ttl int) *KVCache {
	return &KVCache{
		ttl: ttl,
	}
}

//
// LoadFromFile restores the cache from a previous saved file.
//
func LoadFromFile(filepath string) (*KVCache, error) {
	file, err := os.Open(filepath)

	ret := NewCache(0)

	if err == nil {
		decoder := gob.NewDecoder(file)
		err = decoder.Decode(ret)
	}

	file.Close()

	return ret, err
}

//
// SaveToFile saves the current cache into a file.
//
func SaveToFile(filepath string, cache *KVCache) error {
	file, err := os.Create(filepath)

	if err == nil {
		encoder := gob.NewEncoder(file)
		encoder.Encode(cache)
	}

	file.Close()

	return err
}
