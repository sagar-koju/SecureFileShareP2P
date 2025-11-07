using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileShareP2P.Models
{
    public class User
    {
        public int Id { get; set; }

        [Required]
        public string Username { get; set; }

        [Required]
        public string PasswordHash { get; set; }

        [Required]
        public string Salt { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
    }
}
//just checking by sabin