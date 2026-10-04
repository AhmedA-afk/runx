#[cfg(any(feature = "a2a", feature = "mcp"))]
mod argument_template;

#[cfg(feature = "cli-tool")]
pub mod cli_tool;

pub mod javascript;

#[cfg(feature = "a2a")]
pub mod a2a;

#[cfg(feature = "agent")]
pub mod agent;

#[cfg(feature = "agent")]
pub mod agent_loop;

#[cfg(feature = "agent")]
pub mod agent_anthropic;

#[cfg(feature = "agent")]
pub mod agent_openai;

#[cfg(feature = "agent")]
pub mod agent_tool_definitions;

#[cfg(feature = "agent")]
pub mod agent_tools;

#[cfg(feature = "agent")]
pub mod agent_resolver;

#[cfg(feature = "external-adapter")]
pub mod external_adapter;

#[cfg(feature = "mcp")]
pub mod mcp;

#[cfg(feature = "thread-outbox-provider")]
pub mod thread_outbox_provider;
