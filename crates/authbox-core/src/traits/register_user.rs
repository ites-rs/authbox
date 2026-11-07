use std::any::Any;

/// Register user model contract.
/// `as_any` lets YOUR store downcast back to YOUR dto to read custom fields:
///   let dto = input.as_any().downcast_ref::<MyDto>().ok_or("wrong dto")?;
pub trait RegisterUserInput: Send + Sync {
    fn email(&self) -> &str;
    fn password(&self) -> &str;
    fn as_any(&self) -> &dyn Any;
}
