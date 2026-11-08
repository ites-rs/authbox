use async_trait::async_trait;
use std::fmt;
use tracing::{debug, error, info};

use authbox_core::prelude::BoxError;
use authbox_core::traits::EmailProvider;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    address::AddressError,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};

#[derive(Debug)]
pub enum SmtpEmailError {
    InvalidAddress(AddressError),
    Message(lettre::error::Error),
    Transport(lettre::transport::smtp::Error),
}

// BoxError needs a real std Error, so the enum gets Display + Error
impl fmt::Display for SmtpEmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress(e) => write!(f, "invalid recipient address: {e}"),
            Self::Message(e) => write!(f, "failed to build email: {e}"),
            Self::Transport(e) => write!(f, "smtp transport error: {e}"),
        }
    }
}

impl std::error::Error for SmtpEmailError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAddress(e) => Some(e),
            Self::Message(e) => Some(e),
            Self::Transport(e) => Some(e),
        }
    }
}

#[derive(Clone)]
pub struct SmtpEmailProvider {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpEmailProvider {
    pub fn new(host: &str, username: &str, password: &str, from: &str) -> Self {
        let credentials = Credentials::new(username.to_owned(), password.to_owned());

        let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .expect("Failed to create SMTP transport")
            .credentials(credentials)
            .build();

        Self {
            mailer,
            from: from.parse().expect("Invalid FROM address"),
        }
    }
}

#[async_trait]
impl EmailProvider for SmtpEmailProvider {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), BoxError> {
        info!(
            to = %to,
            subject = %subject,
            "Preparing email"
        );

        // used to be an unwrap, which would panic on a bad address
        let to_mailbox = to.parse::<Mailbox>().map_err(|e| {
            error!(to = %to, error = ?e, "Invalid recipient address");
            SmtpEmailError::InvalidAddress(e)
        })?;

        let email = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body.to_owned())
            .map_err(|e| {
                error!(error = ?e, "Failed to build email");
                SmtpEmailError::Message(e)
            })?;

        debug!("Connecting to SMTP server");

        match self.mailer.send(email).await {
            Ok(_) => {
                info!(
                    to = %to,
                    "SMTP email sent successfully"
                );
                Ok(())
            }
            Err(err) => {
                error!(
                    to = %to,
                    error = ?err,
                    "SMTP send failed"
                );
                Err(SmtpEmailError::Transport(err).into())
            }
        }
    }
}