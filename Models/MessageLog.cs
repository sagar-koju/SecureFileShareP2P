// FILE: Models/MessageLog.cs

using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileShareP2P.Models
{
    public class MessageLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string SenderUsername { get; set; }

        [Required]
        public string ReceiverUsername { get; set; }

        [Required]
        public string EncryptedContent { get; set; } // Storing encrypted content for security

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}