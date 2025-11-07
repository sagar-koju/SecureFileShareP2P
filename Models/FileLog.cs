using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileShareP2P.Models
{
    public class FileLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string FileName { get; set; }

        public long FileSize { get; set; }

        [Required]
        public string SenderUsername { get; set; }

        [Required]
        public string ReceiverUsername { get; set; }

        [Required]
        public string Status { get; set; }

        [Required]
        public string OwnerUsername { get; set; }

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}