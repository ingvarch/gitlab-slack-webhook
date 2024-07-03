package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
)

var (
	slackClient *slack.Client
	channelID   string
	gitlabToken string
	port        string
	logger      *log.Logger
)

func main() {
	slackToken := os.Getenv("SLACK_BOT_TOKEN")
	channelID = os.Getenv("SLACK_CHANNEL_ID")
	gitlabToken = os.Getenv("GITLAB_SECRET_TOKEN")
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

	slackClient = slack.New(slackToken)

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
	workInProgress, _ := objectAttrs["work_in_progress"].(bool)
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

	var message string
	if !threadFound {
		message = fmt.Sprintf("[#%d] Merge request update: <%s|%s> by %s\n%s\n", int(globalMRID), url, title, author, url)
		switch action {
		case "open":
			message += "New merge request opened"
		case "close":
			message += "Merge request closed"
		case "merge":
			message += "Merge request merged"
		case "reopen":
			message += "Merge request reopened"
		case "update":
			if workInProgress {
				message += "Marked as DRAFT"
			} else {
				message += "Marked as READY"
			}
		case "approved":
			message += "Merge request approved"
		}
		message += fmt.Sprintf(" by %s", author)
	} else {
		switch action {
		case "open":
			message = fmt.Sprintf("New merge request opened by %s", author)
		case "close":
			message = fmt.Sprintf("Closed by %s", author)
		case "merge":
			message = fmt.Sprintf("Merged by %s", author)
		case "reopen":
			message = fmt.Sprintf("Reopened by %s", author)
		case "update":
			if workInProgress {
				message = fmt.Sprintf("Marked as DRAFT by %s", author)
			} else {
				message = fmt.Sprintf("Marked as READY by %s", author)
			}
		case "approved":
			message = fmt.Sprintf("Approved by %s", author)
		}
	}

	newThreadTS, err := sendSlackMessage(message, threadTS)
	if err != nil {
		logger.Printf("[ERROR] Error sending Slack message: %v", err)
	}

	if !threadFound {
		threadTS = newThreadTS
	}

	if action == "approved" {
		addReaction(threadTS, "white_check_mark")
	}
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
	title, _ := mergeRequest["title"].(string)
	url, _ := mergeRequest["url"].(string)

	note, _ := objectAttrs["note"].(string)
	user, ok := data["user"].(map[string]interface{})
	if !ok {
		logger.Println("[ERROR] Invalid user data in comment payload")
		return
	}
	author, _ := user["name"].(string)

	logger.Printf("[INFO] Processing comment on MR #%d (global ID: %d)", int(mrID), int(globalMRID))

	threadTS, threadFound, err := findOrCreateThreadTS(int(globalMRID))
	if err != nil {
		logger.Printf("[ERROR] Error finding thread for MR #%d (global ID: %d): %v", int(mrID), int(globalMRID), err)
		return
	}

	var message string
	if !threadFound {
		message = fmt.Sprintf("[#%d] New comment on merge request: <%s|%s> by %s\n%s\n\n", int(globalMRID), url, title, author, url)
	}

	position, hasPosition := objectAttrs["position"].(map[string]interface{})
	if hasPosition {
		oldPath, _ := position["old_path"].(string)
		newPath, _ := position["new_path"].(string)
		oldLine, _ := position["old_line"].(float64)
		newLine, _ := position["new_line"].(float64)

		project, _ := data["project"].(map[string]interface{})
		projectURL, _ := project["web_url"].(string)
		commentID, _ := objectAttrs["id"].(float64)
		commentURL := fmt.Sprintf("%s/-/merge_requests/%d#note_%d", projectURL, int(mrID), int(commentID))

		commentInfo := fmt.Sprintf("Code comment by %s:\n", author)
		if oldPath != "" && newPath != "" && oldPath != newPath {
			commentInfo += fmt.Sprintf("File changed: %s -> %s\n", oldPath, newPath)
		} else if newPath != "" {
			commentInfo += fmt.Sprintf("File: %s\n", newPath)
		}
		if oldLine > 0 {
			commentInfo += fmt.Sprintf("Old line: %d\n", int(oldLine))
		}
		if newLine > 0 {
			commentInfo += fmt.Sprintf("Commented line: <%s|%d>\n", commentURL, int(newLine))
		}
		commentInfo += fmt.Sprintf("Comment: %s", note)
		message += commentInfo
	} else {
		message += fmt.Sprintf("New comment by %s:\n\n>%s", author, note)
	}

	_, err = sendSlackMessage(message, threadTS)
	if err != nil {
		logger.Printf("[ERROR] Error sending Slack message: %v", err)
	}
}

func sendSlackMessage(message, threadTS string) (string, error) {
	msgOptions := []slack.MsgOption{
		slack.MsgOptionText(message, false),
	}
	if threadTS != "" {
		msgOptions = append(msgOptions, slack.MsgOptionTS(threadTS))
	}
	_, ts, err := slackClient.PostMessage(channelID, msgOptions...)
	if err != nil {
		logger.Printf("[ERROR] Error sending Slack message: %v", err)
		return "", err
	}
	logger.Printf("[INFO] Successfully sent message to Slack. Timestamp: %s", ts)
	return ts, nil
}

func findOrCreateThreadTS(globalMRID int) (string, bool, error) {
	logger.Printf("[INFO] Searching for thread for MR with global ID: %d", globalMRID)
	params := slack.GetConversationHistoryParameters{
		ChannelID: channelID,
		Limit:     1000,
	}

	searchString := fmt.Sprintf("[#%d]", globalMRID)

	for {
		history, err := slackClient.GetConversationHistory(&params)
		if err != nil {
			return "", false, fmt.Errorf("error getting channel history: %v", err)
		}

		for _, msg := range history.Messages {
			if strings.Contains(msg.Text, searchString) {
				logger.Printf("[INFO] Found thread for MR with global ID %d: %s", globalMRID, msg.Timestamp)
				return msg.Timestamp, true, nil
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

func addReaction(threadTS, reaction string) {
	err := slackClient.AddReaction(reaction, slack.ItemRef{
		Channel:   channelID,
		Timestamp: threadTS,
	})
	if err != nil {
		logger.Printf("[ERROR] Error adding reaction: %v", err)
	} else {
		logger.Printf("[INFO] Successfully added reaction %s to message %s", reaction, threadTS)
	}
}
