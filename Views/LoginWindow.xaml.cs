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

        // === MODIFIED REGISTER BUTTON CLICK HANDLER ===
        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            // Opens the new, dedicated registration window
            var registerWindow = new RegisterWindow();
            registerWindow.ShowDialog(); // ShowDialog makes it modal
        }

        private void UsernameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            // No changes needed here
        }
    }
}