package gitlab

type MRInfo struct {
	Author struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"author"`
}
