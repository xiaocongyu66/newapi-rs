//! 三大核心 channel 适配器的外呼实现（openai / claude / gemini）。其余 45 个
//! 适配器按同一形状逐切片落地。

pub mod claude;
pub mod gemini;
pub mod openai;
