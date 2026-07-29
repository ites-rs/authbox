#![allow(unused)]
#![allow(dead_code)]

use std::env;

use authbox::prelude::{ResendEmailProvider, SendGridEmailProvider, SmtpEmailProvider};

/// Resend provider
pub fn resend_email_provider() -> ResendEmailProvider {
    let api_key = env::var("RESEND_API_KEY").expect("RESEND_API_KEY missing");

    let from_email = env::var("RESEND_FROM_EMAIL").expect("RESEND_FROM_EMAIL missing");

    ResendEmailProvider::new(api_key, from_email)
}

/// SendGrid provider
pub fn sendgrid_email_provider() -> SendGridEmailProvider {
    let api_key = env::var("SENDGRID_API_KEY").expect("SENDGRID_API_KEY missing");

    let from_email = env::var("SENDGRID_FROM_EMAIL").expect("SENDGRID_FROM_EMAIL missing");

    let from_name = env::var("SENDGRID_FROM_NAME").expect("SENDGRID_FROM_NAME missing");

    SendGridEmailProvider::new(api_key, from_email, from_name)
}

/// SMTP provider
pub fn smtp_email_provider() -> SmtpEmailProvider {
    let host = env::var("SMTP_HOST").expect("SMTP_HOST missing"); // smtp.gmail.com

    let username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME missing"); // your email ,

    let password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD missing"); // gmail app password

    let from_email = env::var("SMTP_FROM_EMAIL") // YOUR APP NAME HERE <YOUR EMAIL HERE>
        .expect("SMTP_FROM_EMAIL missing"); // Example -> AuthBox <nyandopeter2@gmail.com>

    SmtpEmailProvider::new(&host, &username, &password, &from_email)
}
