use async_trait::async_trait;
use authbox_core::traits::EmailProvider;
use resend_rs::{Resend, types::CreateEmailBaseOptions};

#[derive(Clone)]
pub struct ResendEmailProvider {
    client: Resend,
    from: String,
}

impl ResendEmailProvider {
    pub fn new(api_key: impl Into<String>, from: impl Into<String>) -> Self {
        Self {
            client: Resend::new(&api_key.into()),
            from: from.into(),
        }
    }
}

#[async_trait]
impl EmailProvider for ResendEmailProvider {
    type Error = resend_rs::Error;

    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), Self::Error> {
        let email = CreateEmailBaseOptions::new(&self.from, [to], subject).with_html(body);

        self.client.emails.send(email).await?;

        Ok(())
    }
}
