package api

import (
	"sort"
	"strings"
)

// ServerFilter defines criteria for filtering the server list.
type ServerFilter struct {
	Country         string // ISO country code (e.g., "US", "CH")
	MinTier         int    // Minimum tier (0=free, 2=plus)
	MaxTier         int    // Maximum tier (0 = no limit)
	Features        int    // Required feature bitmask (OR'd)
	ExcludeFeatures int    // Excluded feature bitmask
	OnlineOnly      bool   // Only include online servers
	FreeOnly        bool   // Only free servers
	SecureCore      bool   // Only Secure Core servers
	P2P             bool   // Only P2P servers
	Tor             bool   // Only Tor servers
	Streaming       bool   // Only streaming servers
	SearchQuery     string // Fuzzy match on name/city/country
	ExcludeName     string // Exclude server by name (for "change server")
}

// FilterServers filters and sorts the server list based on the given criteria.
// Servers are sorted by score (lower is better), then by load (lower is better).
func FilterServers(servers []LogicalServer, filter ServerFilter, userTier int) []LogicalServer {
	var result []LogicalServer

	for _, s := range servers {
		if !matchesFilter(&s, filter, userTier) {
			continue
		}
		result = append(result, s)
	}

	sort.Slice(result, func(i, j int) bool {
		// Primary: score (lower is better)
		if result[i].Score != result[j].Score {
			return result[i].Score < result[j].Score
		}
		// Secondary: load (lower is better)
		return result[i].Load < result[j].Load
	})

	return result
}

func matchesFilter(s *LogicalServer, f ServerFilter, userTier int) bool {
	// Always skip servers the user can't access
	if s.EffectiveTier() > userTier {
		return false
	}

	if f.OnlineOnly && !s.IsOnline() {
		return false
	}

	if f.ExcludeName != "" && strings.EqualFold(s.Name, f.ExcludeName) {
		return false
	}

	if f.Country != "" && !strings.EqualFold(s.ExitCountry, f.Country) {
		return false
	}

	if f.MinTier > 0 && s.EffectiveTier() < f.MinTier {
		return false
	}

	if f.MaxTier > 0 && s.EffectiveTier() > f.MaxTier {
		return false
	}

	if f.FreeOnly && s.Tier != ServerTierFree {
		return false
	}

	if f.Features != 0 && s.Features&f.Features != f.Features {
		return false
	}

	if f.ExcludeFeatures != 0 && s.Features&f.ExcludeFeatures != 0 {
		return false
	}

	if f.SecureCore && !s.IsSecureCore() {
		return false
	}

	if f.P2P && !s.IsP2P() {
		return false
	}

	if f.Tor && !s.IsTor() {
		return false
	}

	if f.Streaming && !s.IsStreaming() {
		return false
	}

	if f.SearchQuery != "" {
		query := strings.ToLower(f.SearchQuery)
		country := strings.ToLower(s.ExitCountry)
		entryCountry := strings.ToLower(s.EntryCountry)
		city := strings.ToLower(s.City)
		name := strings.ToLower(s.Name)

		// 2-char query = exact country code match (avoids "DE" matching "US-DE#1")
		if len(query) == 2 {
			if country != query && entryCountry != query {
				return false
			}
		} else {
			if !strings.Contains(country, query) &&
				!strings.Contains(entryCountry, query) &&
				!strings.Contains(city, query) &&
				!strings.Contains(name, query) {
				return false
			}
		}
	}

	return true
}

// GroupServersByCountry groups servers by their exit country.
func GroupServersByCountry(servers []LogicalServer) map[string][]LogicalServer {
	groups := make(map[string][]LogicalServer)
	for _, s := range servers {
		groups[s.ExitCountry] = append(groups[s.ExitCountry], s)
	}
	return groups
}

// CountryList returns a sorted list of unique exit countries from the server list.
func CountryList(servers []LogicalServer) []string {
	seen := make(map[string]bool)
	var countries []string
	for _, s := range servers {
		if !seen[s.ExitCountry] {
			seen[s.ExitCountry] = true
			countries = append(countries, s.ExitCountry)
		}
	}
	sort.Strings(countries)
	return countries
}

// FindFastestServer returns the best server matching the filter.
// "Best" = lowest score, then lowest load.
func FindFastestServer(servers []LogicalServer, filter ServerFilter, userTier int) *LogicalServer {
	filtered := FilterServers(servers, filter, userTier)
	if len(filtered) == 0 {
		return nil
	}
	return &filtered[0]
}

// FindServerByName finds a server by its name (e.g., "CH#10").
func FindServerByName(servers []LogicalServer, name string) *LogicalServer {
	for i := range servers {
		if strings.EqualFold(servers[i].Name, name) {
			return &servers[i]
		}
	}
	return nil
}
