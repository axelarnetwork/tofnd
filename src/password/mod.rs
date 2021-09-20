//! Get password from standard input and pass them through pbkdf.
//! Available options:
//! [PasswordMethod::Prompt] - Prompt for passwords using [rpassword], and hash them using [scrypt].
//! [PasswordMethod::DefaultPassword] - ** Attention: it is **NOT** safe to use this option **. Avoid inserting a password and use default.

mod constants;
mod password_methods;
mod result;
mod types;

pub use password_methods::PasswordMethod;
