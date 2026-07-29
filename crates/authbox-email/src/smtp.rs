use async_trait::async_trait;
use tracing::{debug, error, info};

use authbox_core::traits::EmailProvider;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};

#[derive(Debug)]
pub enum SmtpEmailError {
    Message(lettre::error::Error),
    Transport(lettre::transport::smtp::Error),
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
    type Error = SmtpEmailError;

    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), Self::Error> {
        info!(
            to = %to,
            subject = %subject,
            "Preparing email"
        );

        let email = Message::builder()
            .from(self.from.clone())
            .to(to.parse::<Mailbox>().unwrap())
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
                Err(SmtpEmailError::Transport(err))
            }
        }
    }
}
