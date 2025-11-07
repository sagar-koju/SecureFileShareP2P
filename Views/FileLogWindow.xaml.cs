using SecureFileShareP2P.Database;
using SecureFileShareP2P.Models;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;

namespace SecureFileShareP2P.Views
{
    public partial class FileLogWindow : Window
    {
        private readonly string _currentUser;

        public ObservableCollection<FileLog> FileLogs { get; } = new ObservableCollection<FileLog>();

        public FileLogWindow(string currentUser)
        {
            InitializeComponent();
            _currentUser = currentUser;
            this.DataContext = this;
            LoadHistory();
        }

        private void LoadHistory()
        {
            FileLogs.Clear();
            try
            {
                using (var db = new AppDbContext())
                {
                    // This now fetches logs where the OwnerUsername is the person currently viewing the history.
                    var logs = db.FileLogs
                        .Where(log => log.OwnerUsername == _currentUser)
                        .OrderByDescending(log => log.Timestamp)
                        .ToList();

                    foreach (var log in logs)
                    {
                        FileLogs.Add(log);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load file history: {ex.Message}", "Database Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            LoadHistory();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}