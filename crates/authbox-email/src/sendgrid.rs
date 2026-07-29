use async_trait::async_trait;
use authbox_core::traits::EmailProvider;
use reqwest::Client;
use serde_json::json;

#[derive(Clone)]
pub struct SendGridEmailProvider {
    api_key: String,
    from_email: String,
    from_name: String,
    client: Client,
}

impl SendGridEmailProvider {
    pub fn new(
        api_key: impl Into<String>,
        from_email: impl Into<String>,
        from_name: impl Into<String>,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            from_email: from_email.into(),
            from_name: from_name.into(),
            client: Client::new(),
        }
    }
}

#[async_trait]
impl EmailProvider for SendGridEmailProvider {
    type Error = reqwest::Error;

    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), Self::Error> {
        self.client
            .post("https://api.sendgrid.com/v3/mail/send")
            .bearer_auth(&self.api_key)
            .json(&json!({
                "personalizations": [{
                    "to": [{
                        "email": to
                    }]
                }],
                "from": {
                    "email": self.from_email,
                    "name": self.from_name
                },
                "subject": subject,
                "content": [{
                    "type": "text/html",
                    "value": body
                }]
            }))
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}
