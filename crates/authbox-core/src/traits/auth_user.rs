/// Auth user model contracts
pub trait AuthUser: Send + Sync {
    fn id(&self) -> String;
    fn email(&self) -> &str;
    fn password_hash(&self) -> &str;
    fn is_email_verified(&self) -> bool;
    fn set_email_verified(&mut self, verified: bool);
    fn set_password_hash(&mut self, hash: String);

    /// Extra public fields for GET /me (name, avatar, role...).
    fn extra(&self) -> Option<serde_json::Value> {
        None
    }
}
