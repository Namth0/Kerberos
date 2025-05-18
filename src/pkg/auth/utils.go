package auth

// Fonction utilitaire pour séparer les chaînes
func SplitString(s, sep string) []string {
	result := make([]string, 0)
	for len(s) > 0 {
		idx := -1
		for i, c := range s {
			if string(c) == sep {
				idx = i
				break
			}
		}
		if idx == -1 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+1:]
	}
	return result
}
