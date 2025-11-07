// FILE: Database/AppDbContext.cs

using Microsoft.EntityFrameworkCore;
using SecureFileShareP2P.Models;

namespace SecureFileShareP2P.Database
{
    public class AppDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<FileLog> FileLogs { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            options.UseSqlite("Data Source=SecureFileShare.db");
        }
    }
}