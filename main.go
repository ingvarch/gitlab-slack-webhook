package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
)

var (
	slackClient    *slack.Client
	channelID      string
	gitlabToken    string
	port           string
	logger         *log.Logger
	gitlabAPIToken string
)

type GitLabMRInfo struct {
	Author struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"author"`
}

func getGitLabMRInfo(projectID int, mrIID int) (*GitLabMRInfo, error) {
	url := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/merge_requests/%d", projectID, mrIID)
	logger.Printf("[INFO] Requesting GitLab MR info: %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("PRIVATE-TOKEN", gitlabAPIToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	logger.Printf("[INFO] GitLab API response status: %s", resp.Status)

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var mrInfo GitLabMRInfo
	if err := json.NewDecoder(resp.Body).Decode(&mrInfo); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	logger.Printf("[INFO] GitLab MR info retrieved successfully. Author username: %s, email: %s", mrInfo.Author.Username, mrInfo.Author.Email)

	return &mrInfo, nil
}

func main() {
	slackToken := os.Getenv("SLACK_BOT_TOKEN")
	channelID = os.Getenv("SLACK_CHANNEL_ID")
	gitlabToken = os.Getenv("GITLAB_SECRET_TOKEN")
	gitlabAPIToken = os.Getenv("GITLAB_API_TOKEN")
	if gitlabAPIToken == "" {
		log.Fatalf("[ERROR] GITLAB_API_TOKEN must be set")
	}
	port = os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if slackToken == "" || channelID == "" || gitlabToken == "" {
		log.Fatalf("[ERROR] SLACK_BOT_TOKEN, SLACK_CHANNEL_ID, and GITLAB_SECRET_TOKEN must be set")
	}

	logger = log.New(os.Stdout, "[GIN] ", log.LstdFlags)
	router := gin.New()
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[GIN] %s - %s %s %s %d %s %s\n",
			param.TimeStamp.Format("2006/01/02 15:04:05"),
			param.ClientIP,
			param.Method,
			param.Path,
			param.StatusCode,
			param.Latency,
			param.ErrorMessage,
		)
	}))
	router.Use(gin.Recovery())

	logger.Println("[INFO] Initializing Gitlab-Slack integration service...")

	slackClient = slack.New(slackToken, slack.OptionDebug(true))

	checkBotPermissions()

	router.POST("/gitlab-webhook", validateGitlabToken, handleGitlabWebhook)

	logger.Printf("[INFO] Starting server on port %s...", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("[ERROR] Failed to start server: %v", err)
	}
}

func checkBotPermissions() {
	logger.Println("[INFO] Checking bot permissions...")

	// Check message permissions
	_, timestamp, err := slackClient.PostMessage(channelID, slack.MsgOptionText("Bot permission test", false))
	if err != nil {
		logger.Printf("[WARN] Unable to post messages to channel %s: %v", channelID, err)
		logger.Println("[INFO] Please ensure the bot has the 'chat:write' scope and is invited to the channel.")
	} else {
		logger.Println("[INFO] Successfully sent a test message to the channel.")

		// Try to delete the test message
		if _, _, err := slackClient.DeleteMessage(channelID, timestamp); err != nil {
			logger.Printf("[WARN] Unable to delete test message. This is not critical: %v", err)
		} else {
			logger.Println("[INFO] Successfully deleted the test message.")
		}

		// Check reaction permissions
		err = slackClient.AddReaction("white_check_mark", slack.ItemRef{Channel: channelID, Timestamp: timestamp})
		if err != nil {
			logger.Printf("[WARN] Unable to add reactions: %v", err)
			logger.Println("[INFO] If you need reaction functionality, ensure the bot has the 'reactions:write' scope.")
		} else {
			logger.Println("[INFO] Successfully checked reaction permissions.")
		}
	}

	logger.Println("[INFO] Bot permissions check completed.")
}

func validateGitlabToken(c *gin.Context) {
	token := c.GetHeader("X-Gitlab-Token")
	if token != gitlabToken {
		logger.Printf("[WARN] Invalid GitLab token received")
		c.AbortWithStatus(401)
		return
	}
	c.Next()
}

func handleGitlabWebhook(c *gin.Context) {
	var data map[string]interface{}
	if err := c.BindJSON(&data); err != nil {
		logger.Printf("[ERROR] Invalid JSON received: %v", err)
		c.JSON(400, gin.H{"error": "Invalid JSON"})
		return
	}
	objectKind, ok := data["object_kind"].(string)
	if !ok {
		logger.Println("[ERROR] Missing object_kind in webhook payload")
		c.JSON(400, gin.H{"error": "Missing object_kind"})
		return
	}
	logger.Printf("[INFO] Received webhook of type: %s", objectKind)
	switch objectKind {
	case "merge_request":
		handleMergeRequest(data)
	case "note":
		handleComment(data)
	default:
		logger.Printf("[WARN] Unhandled object_kind: %s", objectKind)
	}
	c.JSON(200, gin.H{"status": "success"})
}

func handleMergeRequest(data map[string]interface{}) {
	objectAttrs, ok := data["object_attributes"].(map[string]interface{})
	if !ok {
		logger.Println("[ERROR] Invalid object_attributes in merge request payload")
		return
	}
	action, _ := objectAttrs["action"].(string)
	mrID, _ := objectAttrs["iid"].(float64)
	globalMRID, _ := objectAttrs["id"].(float64)
	title, _ := objectAttrs["title"].(string)
	url, _ := objectAttrs["url"].(string)
	description, _ := objectAttrs["description"].(string)
	user, ok := data["user"].(map[string]interface{})
	if !ok {
		logger.Println("[ERROR] Invalid user data in merge request payload")
		return
	}
	author, _ := user["name"].(string)

	logger.Printf("[INFO] Processing MR #%d (global ID: %d), action: %s", int(mrID), int(globalMRID), action)

	threadTS, threadFound, err := findOrCreateThreadTS(int(globalMRID))
	if err != nil {
		logger.Printf("[ERROR] Error finding thread for MR #%d (global ID: %d): %v", int(mrID), int(globalMRID), err)
		return
	}

	if !threadFound {
		threadTS, err = sendInitialSlackMessage(author, url, int(globalMRID), title, description)
		if err != nil {
			logger.Printf("[ERROR] Error sending initial Slack message: %v", err)
			return
		}
		return // Don't send additional messages for new threads
	}

	var message string
	switch action {
	case "close":
		message = fmt.Sprintf("Merge request closed by %s", author)
	case "merge":
		message = fmt.Sprintf("Merge request merged by %s", author)
	case "reopen":
		message = fmt.Sprintf("Merge request reopened by %s", author)
	case "update":
		message = fmt.Sprintf("Merge request updated by %s", author)
	case "approved":
		err = updateParentMessageWithApproval(threadTS, author)
		if err != nil {
			logger.Printf("[ERROR] Error updating parent Slack message: %v", err)
		}

		// Getting info about MR author and notifying him
		projectID, _ := data["project"].(map[string]interface{})["id"].(float64)
		mrInfo, err := getGitLabMRInfo(int(projectID), int(mrID))
		if err != nil {
			logger.Printf("[ERROR] Could not get MR info from GitLab: %v", err)
		} else {
			slackUserID, err := getSlackUserIDByGitLabInfo(mrInfo.Author.Username, mrInfo.Author.Email)
			if err != nil {
				logger.Printf("[WARN] Could not find Slack user for GitLab user %s: %v", mrInfo.Author.Username, err)
			} else {
				message = fmt.Sprintf("Hey <@%s>, your MR is ready to merge!", slackUserID)
			}
		}
	case "unapproved":
		message = fmt.Sprintf("Approval revoked by %s", author)
		err = updateParentMessageRemoveApproval(threadTS, author)
		if err != nil {
			logger.Printf("[ERROR] Error updating parent Slack message: %v", err)
		}
	}

	if message != "" {
		err = sendThreadMessage(message, threadTS)
		if err != nil {
			logger.Printf("[ERROR] Error sending thread message: %v", err)
		}
	}
}

func findOrCreateThreadTS(globalMRID int) (string, bool, error) {
	logger.Printf("[INFO] Searching for thread for MR with global ID: %d", globalMRID)
	params := slack.GetConversationHistoryParameters{
		ChannelID: channelID,
		Limit:     1000,
	}

	searchString := fmt.Sprintf("#%d", globalMRID)

	for {
		history, err := slackClient.GetConversationHistory(&params)
		if err != nil {
			return "", false, fmt.Errorf("error getting channel history: %v", err)
		}

		for _, msg := range history.Messages {
			// Check if the message text contains the search string
			if strings.Contains(msg.Text, searchString) {
				logger.Printf("[INFO] Found thread for MR with global ID %d: %s", globalMRID, msg.Timestamp)
				return msg.Timestamp, true, nil
			}
			// Check if any block text contains the search string
			for _, block := range msg.Blocks.BlockSet {
				if sectionBlock, ok := block.(*slack.SectionBlock); ok && sectionBlock.Text != nil {
					if strings.Contains(sectionBlock.Text.Text, searchString) {
						logger.Printf("[INFO] Found thread for MR with global ID %d: %s", globalMRID, msg.Timestamp)
						return msg.Timestamp, true, nil
					}
				}
			}
		}

		if !history.HasMore {
			break
		}
		params.Cursor = history.ResponseMetaData.NextCursor
	}

	logger.Printf("[INFO] Thread for MR with global ID %d not found", globalMRID)
	return "", false, nil
}

func getSlackUserIDByEmail(email string) (string, error) {
	logger.Printf("[INFO] Attempting to get Slack user ID for email: %s", email)
	user, err := slackClient.GetUserByEmail(email)
	if err != nil {
		logger.Printf("[WARN] Error getting user by email: %v", err)
		if err.Error() == "users_not_found" {
			logger.Printf("[INFO] User not found by email, trying to find user by iterating through all users")
			users, err := slackClient.GetUsers()
			if err != nil {
				logger.Printf("[ERROR] Error getting Slack users: %v", err)
				return "", fmt.Errorf("error getting Slack users: %v", err)
			}
			for _, u := range users {
				logger.Printf("[DEBUG] Checking user: %s, email: %s", u.Name, u.Profile.Email)
				if u.Profile.Email == email {
					logger.Printf("[INFO] Found matching user: %s", u.ID)
					return u.ID, nil
				}
			}
			logger.Printf("[WARN] No matching user found after checking all users")
		}
		return "", err
	}
	logger.Printf("[INFO] Successfully found Slack user ID: %s", user.ID)
	return user.ID, nil
}

func getSlackUserIDByGitLabInfo(gitlabUsername, gitlabEmail string) (string, error) {
	logger.Printf("[INFO] Attempting to get Slack user ID for GitLab username: %s, email: %s", gitlabUsername, gitlabEmail)

	if gitlabEmail != "" {
		userID, err := getSlackUserIDByEmail(gitlabEmail)
		if err == nil {
			return userID, nil
		}
		logger.Printf("[WARN] Could not find user by email: %v", err)
	}

	users, err := slackClient.GetUsers()
	if err != nil {
		return "", fmt.Errorf("error getting Slack users: %v", err)
	}

	for _, user := range users {
		logger.Printf("[DEBUG] Checking user: %s, email: %s, real name: %s, display name: %s",
			user.Name, user.Profile.Email, user.RealName, user.Profile.DisplayName)

		// Exclude system users and bots
		if user.IsBot || user.ID == "USLACKBOT" {
			continue
		}

		if strings.EqualFold(user.Profile.Email, gitlabEmail) ||
			strings.EqualFold(user.Name, gitlabUsername) ||
			strings.EqualFold(user.Profile.DisplayName, gitlabUsername) ||
			strings.EqualFold(user.RealName, gitlabUsername) {
			logger.Printf("[INFO] Found exact match for user: %s", user.ID)
			return user.ID, nil
		}

		// If there is no exact match, check for partial match
		if strings.Contains(strings.ToLower(user.RealName), strings.ToLower(gitlabUsername)) ||
			strings.Contains(strings.ToLower(user.Profile.DisplayName), strings.ToLower(gitlabUsername)) {
			logger.Printf("[INFO] Found partial match for user: %s", user.ID)
			return user.ID, nil
		}
	}

	return "", fmt.Errorf("no matching Slack user found for GitLab username: %s, email: %s", gitlabUsername, gitlabEmail)
}

func handleComment(data map[string]interface{}) {
	objectAttrs, ok := data["object_attributes"].(map[string]interface{})
	if !ok {
		logger.Println("[ERROR] Invalid object_attributes in comment payload")
		return
	}
	noteableType, _ := objectAttrs["noteable_type"].(string)
	if noteableType != "MergeRequest" {
		logger.Printf("[INFO] Ignoring comment on %s", noteableType)
		return
	}

	mergeRequest, ok := data["merge_request"].(map[string]interface{})
	if !ok {
		logger.Println("[ERROR] Invalid merge_request data in comment payload")
		return
	}
	mrID, _ := mergeRequest["iid"].(float64)
	globalMRID, _ := mergeRequest["id"].(float64)

	note, _ := objectAttrs["note"].(string)
	noteURL, _ := objectAttrs["url"].(string)

	logger.Printf("[INFO] Processing comment on MR #%d (global ID: %d)", int(mrID), int(globalMRID))

	threadTS, threadFound, err := findOrCreateThreadTS(int(globalMRID))
	if err != nil {
		logger.Printf("[ERROR] Error finding thread for MR #%d (global ID: %d): %v", int(mrID), int(globalMRID), err)
		return
	}

	if !threadFound {
		logger.Printf("[ERROR] Thread not found for MR #%d (global ID: %d)", int(mrID), int(globalMRID))
		return
	}

	message := fmt.Sprintf("New comment on merge request: <%s|View comment>\n>%s", noteURL, note)

	err = sendThreadMessage(message, threadTS)
	if err != nil {
		logger.Printf("[ERROR] Error sending thread message: %v", err)
	}
}

func sendThreadMessage(message, threadTS string) error {
	msgOptions := []slack.MsgOption{
		slack.MsgOptionText(message, false),
		slack.MsgOptionTS(threadTS),
	}
	_, _, err := slackClient.PostMessage(channelID, msgOptions...)
	if err != nil {
		logger.Printf("[ERROR] Error sending thread Slack message: %v", err)
		return err
	}
	logger.Printf("[INFO] Successfully sent thread message to Slack.")
	return nil
}

func sendInitialSlackMessage(author, url string, mrID int, title, description string) (string, error) {
	blocks := []slack.Block{
		slack.NewSectionBlock(&slack.TextBlockObject{
			Type: slack.MarkdownType,
			Text: fmt.Sprintf("Merge request opened by %s", author),
		}, nil, nil),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(&slack.TextBlockObject{
			Type: slack.MarkdownType,
			Text: fmt.Sprintf("<%s|#%d %s>", url, mrID, title),
		}, nil, nil),
	}

	if description != "" {
		blocks = append(blocks,
			slack.NewDividerBlock(),
			slack.NewSectionBlock(&slack.TextBlockObject{
				Type: slack.MarkdownType,
				Text: fmt.Sprintf("Description:\n%s", description),
			}, nil, nil),
		)
	}

	msgOptions := []slack.MsgOption{
		slack.MsgOptionBlocks(blocks...),
	}

	_, ts, err := slackClient.PostMessage(channelID, msgOptions...)
	if err != nil {
		logger.Printf("[ERROR] Error sending initial Slack message: %v", err)
		return "", err
	}
	logger.Printf("[INFO] Successfully sent initial message to Slack. Timestamp: %s", ts)
	return ts, nil
}

func updateParentMessageWithApproval(threadTS string, author string) error {
	historyParams := &slack.GetConversationHistoryParameters{
		ChannelID: channelID,
		Inclusive: true,
		Latest:    threadTS,
		Limit:     1,
	}

	history, err := slackClient.GetConversationHistory(historyParams)
	if err != nil {
		logger.Printf("[ERROR] Failed to retrieve message history: %v", err)
		return err
	}

	if len(history.Messages) != 1 {
		return fmt.Errorf("failed to retrieve the original message")
	}

	originalMessage := history.Messages[0]
	originalBlocks := originalMessage.Blocks.BlockSet

	// Check if approval block already exists
	approvalBlockIndex := -1
	for i, block := range originalBlocks {
		if block.BlockType() == slack.MBTContext {
			approvalBlockIndex = i
			break
		}
	}

	approvalText := fmt.Sprintf(":white_check_mark: Approved by %s", author)
	if approvalBlockIndex != -1 {
		// Update existing approval block
		contextBlock := originalBlocks[approvalBlockIndex].(*slack.ContextBlock)
		existingText := contextBlock.ContextElements.Elements[0].(*slack.TextBlockObject).Text
		updatedText := existingText + ", " + author
		contextBlock.ContextElements.Elements[0] = slack.NewTextBlockObject("mrkdwn", updatedText, false, false)
	} else {
		// Add new approval block
		approvalContextBlock := slack.NewContextBlock("approval_context", slack.NewTextBlockObject("mrkdwn", approvalText, false, false))
		originalBlocks = append(originalBlocks, approvalContextBlock)
	}

	return updateSlackMessage("", threadTS, originalBlocks)
}

func updateSlackMessage(message, threadTS string, blocks []slack.Block) error {
	msgOptions := []slack.MsgOption{
		slack.MsgOptionText(message, false),
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionTS(threadTS),
	}
	_, _, _, err := slackClient.UpdateMessage(channelID, threadTS, msgOptions...)
	if err != nil {
		logger.Printf("[ERROR] Error updating Slack message: %v", err)
		return err
	}
	logger.Printf("[INFO] Successfully updated message in Slack. Timestamp: %s", threadTS)
	return nil
}

func updateParentMessageRemoveApproval(threadTS string, author string) error {
	historyParams := &slack.GetConversationHistoryParameters{
		ChannelID: channelID,
		Inclusive: true,
		Latest:    threadTS,
		Limit:     1,
	}

	history, err := slackClient.GetConversationHistory(historyParams)
	if err != nil {
		logger.Printf("[ERROR] Failed to retrieve message history: %v", err)
		return err
	}

	if len(history.Messages) != 1 {
		return fmt.Errorf("failed to retrieve the original message")
	}

	originalMessage := history.Messages[0]
	originalBlocks := originalMessage.Blocks.BlockSet

	// Find and remove approval block
	approvalBlockIndex := -1
	for i, block := range originalBlocks {
		if block.BlockType() == slack.MBTContext {
			approvalBlockIndex = i
			break
		}
	}

	if approvalBlockIndex != -1 {
		// Remove approval block
		originalBlocks = append(originalBlocks[:approvalBlockIndex], originalBlocks[approvalBlockIndex+1:]...)
	}

	return updateSlackMessage("", threadTS, originalBlocks)
}
