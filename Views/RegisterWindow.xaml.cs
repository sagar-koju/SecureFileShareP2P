using SecureFileShareP2P.Services;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;

namespace SecureFileShareP2P.Views
{
    public partial class RegisterWindow : Window
    {
        public RegisterWindow()
        {
            InitializeComponent();
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            string email = EmailTextBox.Text;
            string password = PasswordBox.Password;
            string passwordConfirm = ConfirmPasswordBox.Password;

            // 1. Basic Field Validation 
            if (string.IsNullOrWhiteSpace(FullNameTextBox.Text) ||
                string.IsNullOrWhiteSpace(email) ||
                string.IsNullOrWhiteSpace(UsernameTextBox.Text) ||
                string.IsNullOrWhiteSpace(password))
            {
                MessageBox.Show("All fields are required.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 2. Email Format Validation 
            if (!IsValidEmail(email))
            {
                MessageBox.Show("Please enter a valid email address.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 3. Password Strength Validation 
            if (!IsValidPassword(password, out string passwordError))
            {
                MessageBox.Show(passwordError, "Weak Password", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 4. Password Match Validation 
            if (password != passwordConfirm)
            {
                MessageBox.Show("Passwords do not match.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // If all validation passes, proceed with registration 
            bool success = AuthService.Register(
                UsernameTextBox.Text,
                password,
                FullNameTextBox.Text,
                email
            );

            if (success)
            {
                MessageBox.Show("Registration successful! You can now log in.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                this.Close(); // Close the registration window
            }
            else
            {
                MessageBox.Show("This username is already taken. Please choose another.", "Registration Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        /// <summary>
        /// Validates an email address using a regular expression.
        /// </summary>
        private bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            try
            {
                // A common and reasonably effective regex for email validation.
                return Regex.IsMatch(email,
                    @"^[^@\s]+@[^@\s]+\.[^@\s]+$",
                    RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }

        /// <summary>
        /// Validates password strength based on defined rules.
        /// </summary>
        private bool IsValidPassword(string password, out string errorMessage)
        {
            errorMessage = string.Empty;

            if (password.Length < 5)
            {
                errorMessage = "Password must be at least 8 characters long.";
                return false;
            }

            return true;
        }
    }
}