using SecureFileShareP2P.Services;
using System.Windows;
using System.Windows.Controls;

namespace SecureFileShareP2P.Views
{
    public partial class LoginWindow : Window
    {
        public LoginWindow()
        {
            InitializeComponent();
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(UsernameTextBox.Text))
            {
                MessageBox.Show("Username is required.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                UsernameTextBox.Focus();
                return; 
            }

            if (string.IsNullOrEmpty(PasswordBox.Password))
            {
                MessageBox.Show("Password is required.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                PasswordBox.Focus();
                return;
            }
            string username = UsernameTextBox.Text;
            if (AuthService.Login(username, PasswordBox.Password))
            {
                MessageBox.Show("Login successful!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);

                var mainWindow = new MainWindow(username);
                mainWindow.Show();
                this.Close();
            }
            else
            {
                MessageBox.Show("Invalid credentials!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            var registerWindow = new RegisterWindow();
            registerWindow.ShowDialog(); 
        }

        private void UsernameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            
        }
    }
}