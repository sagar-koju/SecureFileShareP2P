using System;

namespace SecureFileShareP2P.Models
{
    /// <summary>
    /// Represents the sender of a chat message.
    /// </summary>
    public enum MessageSender
    {
        LocalUser,  // You
        RemoteUser, // The other person
        System      // For status messages like "[Connection lost]"
    }

    /// <summary>
    /// Represents a single message in a chat conversation.
    /// </summary>
    public class ChatMessage
    {
        public string Content { get; set; }
        public MessageSender Sender { get; set; }
        public DateTime Timestamp { get; set; }
    }
}