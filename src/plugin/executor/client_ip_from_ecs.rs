// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `client_ip_from_ecs` executor plugin.
//!
//! Replaces the request-local client IP with the address carried by an EDNS
//! Client Subnet (ECS) option, such as one added by dnsmasq `--add-subnet`.
//! The plugin has no configuration or external dependencies and only mutates
//! [`DnsContext`]; place it before client-IP matchers and recorders. It
//! performs no allocation, locking, or I/O on the request path.

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::infra::error::Result;
use crate::infra::network::ip::normalize_ipv4_mapped_ip;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, UninitializedPlugin};
use crate::plugin_factory;
use crate::proto::{EdnsCode, EdnsOption};

#[derive(Debug)]
struct ClientIpFromEcs {
    tag: String,
}

#[async_trait]
impl Plugin for ClientIpFromEcs {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for ClientIpFromEcs {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let ecs_addr = context
            .request()
            .edns()
            .as_ref()
            .and_then(|edns| edns.option(EdnsCode::Subnet))
            .and_then(|option| match option {
                // A zero-length prefix intentionally conveys no client address.
                EdnsOption::Subnet(subnet) if subnet.source_prefix() != 0 => {
                    Some(normalize_ipv4_mapped_ip(subnet.addr()))
                }
                _ => None,
            });

        if let Some(ip) = ecs_addr {
            let port = context.peer_addr().port();
            context.set_peer_addr(SocketAddr::new(ip, port));
        }

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
#[plugin_factory("client_ip_from_ecs")]
pub struct ClientIpFromEcsFactory;

impl PluginFactory for ClientIpFromEcsFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _init_context: &crate::plugin::PluginInitContext<'_>,
    ) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(ClientIpFromEcs {
            tag: plugin_config.tag.clone(),
        })))
    }

    fn quick_setup(&self, tag: &str, _param: Option<String>) -> Result<UninitializedPlugin> {
        Ok(UninitializedPlugin::Executor(Box::new(ClientIpFromEcs {
            tag: tag.to_string(),
        })))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::*;
    use crate::plugin::test_utils::test_context;
    use crate::proto::{ClientSubnet, EdnsOption};

    fn add_ecs(context: &mut DnsContext, addr: IpAddr, prefix: u8) {
        context
            .request_mut()
            .ensure_edns_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix, 0)));
    }

    fn plugin() -> ClientIpFromEcs {
        ClientIpFromEcs {
            tag: "client_ip_from_ecs".to_string(),
        }
    }

    #[tokio::test]
    async fn replaces_ip_and_preserves_port() {
        let mut context = test_context();
        context.set_peer_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 5353)));
        add_ecs(&mut context, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123)), 32);

        assert_eq!(
            plugin().execute(&mut context).await.unwrap(),
            ExecStep::Next
        );
        assert_eq!(
            context.peer_addr(),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 123), 5353))
        );
    }

    #[tokio::test]
    async fn supports_ipv6_ecs() {
        let mut context = test_context();
        let ecs_ip = Ipv6Addr::new(0x2001, 0xDB8, 1, 2, 0, 0, 0, 0);
        add_ecs(&mut context, IpAddr::V6(ecs_ip), 64);

        plugin().execute(&mut context).await.unwrap();
        assert_eq!(context.peer_addr().ip(), IpAddr::V6(ecs_ip));
    }

    #[tokio::test]
    async fn leaves_client_ip_unchanged_without_usable_ecs() {
        let mut without_ecs = test_context();
        let original = without_ecs.peer_addr();
        plugin().execute(&mut without_ecs).await.unwrap();
        assert_eq!(without_ecs.peer_addr(), original);

        let mut zero_prefix = test_context();
        let original = zero_prefix.peer_addr();
        add_ecs(&mut zero_prefix, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        plugin().execute(&mut zero_prefix).await.unwrap();
        assert_eq!(zero_prefix.peer_addr(), original);
    }
}
